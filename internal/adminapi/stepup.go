package adminapi

import (
	"net/http"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
)

// Operacje o najwiekszym wplywie wymagaja swiezego uwierzytelnienia i podania
// powodu. Chodzi o zmiany, ktore przestawiaja same reguly dostepu: mapowanie
// grup na role, nadanie uprawnien tozsamosci, globalne reguly katalogu.
//
// Panel nie realizuje MFA i nie udaje, ze je zna. MFA nalezy do dostawcy
// tozsamosci; panel sprawdza wylacznie, czy dostal zadeklarowany poziom
// uwierzytelnienia (acr) i czy uwierzytelnienie jest swieze. Gdy instalacja
// nie zdefiniowala poziomu, zostaje sama swiezosc - i tak jest to zapisane
// w audycie, zeby nikt nie odczytal tego jako potwierdzenia MFA.
type stepUpPolicy struct {
	// MaxAge jest dopuszczalnym wiekiem uwierzytelnienia. Zero wylacza
	// wymaganie swiezosci.
	MaxAge time.Duration
	// ACR jest wymaganym poziomem uwierzytelnienia. Puste oznacza, ze
	// instalacja go nie zdefiniowala.
	ACR string
}

const minimalStepUpReason = 8

// stepUpDenial opisuje odmowe wraz z tym, czego brakuje. Klient ma z tego
// poznac, ze warto przeprowadzic ponowne uwierzytelnienie i ponowic zadanie.
type stepUpDenial struct {
	Code    string
	Message string
	Detail  map[string]any
}

// evaluate rozstrzyga, czy operacja o najwiekszym wplywie moze sie odbyc.
// Funkcja nie ma skutkow ubocznych: zapis do audytu i odpowiedz HTTP naleza
// do warstwy wyzej, dzieki czemu sama regula da sie sprawdzic w tescie.
func (p stepUpPolicy) evaluate(reason string, session *authz.Session) (map[string]any, *stepUpDenial) {
	reason = strings.TrimSpace(reason)
	if len([]rune(reason)) < minimalStepUpReason {
		return nil, &stepUpDenial{
			Code:    "reason_required",
			Message: "this operation requires a reason (field reason, min. 8 characters)",
			Detail:  map[string]any{},
		}
	}

	if session == nil {
		// Tozsamosc automatyczna nie moze przejsc ponownego uwierzytelnienia:
		// nie ma za nia czlowieka. Operacja jest dopuszczona, ale audyt
		// zapisuje wprost, ze uwierzytelnienia nie odswiezono.
		return map[string]any{
			"high_impact": true, "purpose": reason,
			"authentication": "api_token", "reauthenticated": false,
		}, nil
	}

	if p.MaxAge > 0 {
		if session.Auth.At.IsZero() {
			// Dostawca nie podal auth_time. Stan nieustalony nie moze byc
			// czytany jako "przed chwila".
			return nil, &stepUpDenial{
				Code:    "reauthentication_required",
				Message: "the identity provider did not report the authentication time; sign in again",
				Detail:  map[string]any{"required_max_age_seconds": int(p.MaxAge.Seconds())},
			}
		}
		if age := time.Since(session.Auth.At); age > p.MaxAge {
			return nil, &stepUpDenial{
				Code:    "reauthentication_required",
				Message: "this operation requires fresh authentication; sign in again",
				Detail: map[string]any{
					"required_max_age_seconds":   int(p.MaxAge.Seconds()),
					"authentication_age_seconds": int(age.Seconds()),
				},
			}
		}
	}
	if p.ACR != "" && session.Auth.ACR != p.ACR {
		return nil, &stepUpDenial{
			Code:    "reauthentication_required",
			Message: "this operation requires authentication at level " + p.ACR,
			Detail:  map[string]any{"required_acr": p.ACR, "session_acr": session.Auth.ACR},
		}
	}

	return map[string]any{
		"high_impact": true, "purpose": reason,
		"authentication": "session", "reauthenticated": true,
		// Sposob uwierzytelnienia zapisujemy tak, jak podal go dostawca.
		// Panel nie tlumaczy tego na wlasne "mfa: tak".
		"acr": session.Auth.ACR, "amr": session.Auth.AMR,
		"authenticated_at": session.Auth.At.UTC().Format(time.RFC3339),
	}, nil
}

// requireStepUp stosuje regule i zwraca dowod uwierzytelnienia do zapisania
// w audycie samej operacji.
//
// Odmowa jest audytowana tutaj, bo operacja nigdy nie dochodzi do skutku.
// Powodzenie audytuje handler razem z opisem zmiany: jedna operacja ma
// zostawiac jeden wpis, a nie dwa mowiace o tym samym.
func (s *Server) requireStepUp(w http.ResponseWriter, r *http.Request,
	principal authz.Principal, reason, action, targetType, targetID string) (map[string]any, bool) {
	session, _ := authz.SessionFromContext(r.Context())

	evidence, denial := s.stepUp.evaluate(reason, session)
	if denial != nil {
		denial.Detail["reason"] = denial.Code
		denial.Detail["action"] = action
		s.audit.Record(r.Context(), audit.Event{
			ActorType: audit.ActorUser, ActorID: principal.Subject,
			Action: action, TargetType: targetType, TargetID: targetID,
			RequestID: requestIDOf(r), Outcome: audit.OutcomeDenied, Detail: denial.Detail,
		})
		// 401 zamiast 403: brakuje swiezego uwierzytelnienia, a nie uprawnien.
		problem(w, http.StatusUnauthorized, denial.Code, denial.Message)
		return nil, false
	}
	return evidence, true
}

// withStepUp dokleja dowod uwierzytelnienia do opisu zmiany. Dzieki temu
// jeden wpis audytu mowi i co sie zmienilo, i na jakiej podstawie.
func withStepUp(detail, evidence map[string]any) map[string]any {
	for key, value := range evidence {
		detail[key] = value
	}
	return detail
}
