package helper

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/schedules"
)

// applySchedule obsluguje zadania cykliczne.
//
// Wpisy zarzadzane maja wlasne pliki w /etc/cron.d i stabilne identyfikatory.
// Wpis zastany nalezy do administratora hosta: panel go widzi, ale nie
// nadpisuje bez jawnego przejecia - inaczej pierwsza operacja z panelu
// kasowalaby prace, ktorej nikt do panelu nie wprowadzal.
func (s *Server) applySchedule(ctx context.Context, request *helperv1.HelperRequest,
	action *helperv1.ScheduleRequest) *helperv1.HelperResponse {
	// Wpisy crona i jednostki systemd dziela ten sam zasob hosta: rownolegly
	// zapis dwoch wpisow moze zostawic katalog w stanie posrednim.
	if !s.unitMutex.TryLock() {
		return reject(ErrorLocked, "inna operacja na jednostkach jest w toku")
	}
	defer s.unitMutex.Unlock()

	timeout := time.Duration(request.GetTimeoutSeconds()) * time.Second
	if timeout <= 0 || timeout > 30*time.Minute {
		timeout = 5 * time.Minute
	}
	actionCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	switch action.GetOperation() {
	case helperv1.ScheduleRequest_OPERATION_READ:
		return odpowiedzHarmonogramow(s.czytajHarmonogramy(actionCtx), "")

	case helperv1.ScheduleRequest_OPERATION_ENSURE:
		return s.zapewnijWpis(actionCtx, action)

	case helperv1.ScheduleRequest_OPERATION_DISABLE:
		return s.przelaczWpis(actionCtx, action)

	case helperv1.ScheduleRequest_OPERATION_REMOVE:
		if err := schedules.UsunWpis(schedules.KatalogCronD, action.GetId()); err != nil {
			return reject(ErrorExecFailed, err.Error())
		}
		return odpowiedzHarmonogramow(s.czytajHarmonogramy(actionCtx),
			"wpis "+action.GetId()+" usuniety")

	case helperv1.ScheduleRequest_OPERATION_RUN_NOW:
		return s.uruchomTeraz(actionCtx, action)
	}
	return reject(ErrorUnknownAction, "nieznana operacja na harmonogramie")
}

// zapewnijWpis zaklada albo aktualizuje wpis zarzadzany.
func (s *Server) zapewnijWpis(ctx context.Context, action *helperv1.ScheduleRequest) *helperv1.HelperResponse {
	// Wpis o tym samym identyfikatorze moze juz istniec jako zastany.
	// Nadpisanie go bez zgody operatora skasowaloby cudza prace.
	kolizja := s.wpisZastany(ctx, action.GetId())
	if kolizja != nil && !action.GetAdopt() {
		return reject(ErrorUnsupported, fmt.Sprintf(
			"wpis o tej nazwie istnieje juz na hoscie (%s, linia %d) i nie nalezy do panelu; "+
				"przejecie wymaga jawnej zgody", kolizja.Path, kolizja.Line))
	}
	// Przejecie musi usunac wpis zastany. Zostawiony obok wpisu panelu
	// uruchamialby to samo zadanie drugi raz - a operator prosil o jedno.
	if kolizja != nil && filepath.Dir(kolizja.Path) != schedules.KatalogCronD {
		return reject(ErrorUnsupported, fmt.Sprintf(
			"wpis lezy w %s (linia %d); panel nie przepisuje tego pliku, "+
				"usun tam wiersz recznie przed przejeciem", kolizja.Path, kolizja.Line))
	}

	wpis := schedules.Schedule{
		ID:         action.GetId(),
		Expression: action.GetExpression(),
		Command:    action.GetCommand(),
		User:       action.GetUser(),
		Comment:    action.GetComment(),
		Enabled:    true,
	}
	if err := schedules.ZapiszWpis(schedules.KatalogCronD, wpis); err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	komunikat := "wpis " + wpis.ID + " zapisany"
	if kolizja != nil {
		if err := os.Remove(kolizja.Path); err != nil {
			return reject(ErrorExecFailed, "wpis zapisany, ale nie usunieto przejmowanego "+
				kolizja.Path+": "+err.Error())
		}
		komunikat += "; przejeto i usunieto " + kolizja.Path
	}
	return odpowiedzHarmonogramow(s.czytajHarmonogramy(ctx), komunikat)
}

// przelaczWpis wlacza albo wylacza wpis zarzadzany. Wylaczenie zostawia tresc
// na hoscie: wylaczenie nie jest usunieciem.
func (s *Server) przelaczWpis(ctx context.Context, action *helperv1.ScheduleRequest) *helperv1.HelperResponse {
	obecny := s.wpisZarzadzany(ctx, action.GetId())
	if obecny == nil {
		return reject(ErrorUnsupported, "wpis "+action.GetId()+" nie nalezy do panelu")
	}
	obecny.Enabled = action.GetEnabled()
	if err := schedules.ZapiszWpis(schedules.KatalogCronD, *obecny); err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	stan := "wylaczony"
	if obecny.Enabled {
		stan = "wlaczony"
	}
	return odpowiedzHarmonogramow(s.czytajHarmonogramy(ctx), "wpis "+obecny.ID+" "+stan)
}

// uruchomTeraz wykonuje polecenie wpisu poza harmonogramem.
//
// Uruchamiane jest wylacznie polecenie wpisu zarzadzanego: wpis zastany
// bywa wierszem powloki, ktorego panel nie rozbiera na argumenty, a
// uruchomienie go przez powloke byloby dokladnie tym, czego ten modul
// unika.
func (s *Server) uruchomTeraz(ctx context.Context, action *helperv1.ScheduleRequest) *helperv1.HelperResponse {
	wpis := s.wpisZarzadzany(ctx, action.GetId())
	if wpis == nil {
		return reject(ErrorUnsupported, "wpis "+action.GetId()+" nie nalezy do panelu")
	}
	if len(wpis.Command) == 0 {
		return reject(ErrorMalformed, "wpis nie ma polecenia")
	}

	cmd := polecenieWpisu(ctx, wpis)
	wyjscie, err := cmd.CombinedOutput()
	komunikat := strings.TrimSpace(string(wyjscie))
	if len(komunikat) > 4000 {
		komunikat = komunikat[len(komunikat)-4000:]
	}
	if err != nil {
		response := reject(ErrorExecFailed, err.Error())
		response.ScheduleResult = &helperv1.ScheduleResult{Message: komunikat}
		return response
	}
	return odpowiedzHarmonogramow(s.czytajHarmonogramy(ctx),
		"wpis "+wpis.ID+" uruchomiony; "+komunikat)
}

// polecenieWpisu sklada uruchomienie polecenia wpisu.
//
// Uruchomienie recznie ma dac to samo, co uruchomienie z harmonogramu.
// Helper dziala z PrivateTmp=yes, wiec polecenie odpalone jako jego proces
// potomny widzi inny /tmp niz to samo polecenie odpalone przez crona -
// a wtedy "Run now" sprawdzalby cos innego niz to, co dzieje sie w nocy.
// Jednostka przejsciowa systemd wraca do przestrzeni nazw hosta i przy okazji
// daje wykonaniu wlasna grupe kontrolna i slad w dzienniku.
func polecenieWpisu(ctx context.Context, wpis *schedules.Schedule) *exec.Cmd {
	srodowisko := []string{"LC_ALL=C", "LANG=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/root"}
	sciezkaSystemdRun, err := exec.LookPath("systemd-run")
	if err != nil {
		// Host bez systemd nie ma tez PrivateTmp helpera, wiec bezposrednie
		// uruchomienie jest tu rownowazne.
		cmd := exec.CommandContext(ctx, wpis.Command[0], wpis.Command[1:]...)
		cmd.Env = srodowisko
		return cmd
	}
	argumenty := []string{"--collect", "--wait", "--pipe", "--quiet",
		"--unit=flotestro-schedule-" + wpis.ID,
		"--description=Flotestro: " + wpis.ID}
	if wpis.User != "" {
		argumenty = append(argumenty, "--uid="+wpis.User)
	}
	argumenty = append(argumenty, "--")
	argumenty = append(argumenty, wpis.Command...)
	cmd := exec.CommandContext(ctx, sciezkaSystemdRun, argumenty...)
	cmd.Env = srodowisko
	return cmd
}

// czytajHarmonogramy sklada obraz zadan cyklicznych hosta.
func (s *Server) czytajHarmonogramy(ctx context.Context) schedules.Snapshot {
	teraz := time.Now()
	snapshot := schedules.Snapshot{
		Schedules: schedules.CzytajCron(schedules.SciezkaCrontabu, schedules.KatalogCronD, teraz),
		// Strefa pochodzi z konfiguracji hosta, a nie z nazwy time.Local:
		// ta ostatnia to zawsze "Local" i nie mowi operatorowi niczego.
		Timezone: schedules.StrefaHosta(),
	}
	snapshot.Schedules = append(snapshot.Schedules,
		schedules.CzytajTimery(
			wyjscieSystemctl(ctx, "list-timers", "--all", "--no-pager", "--no-legend"),
			wyjscieSystemctl(ctx, "list-units", "--type=timer", "--all", "--no-pager", "--no-legend", "--plain"),
			wyjscieSystemctl(ctx, "show", "--property=Id", "--property=TimersCalendar", "*.timer"))...)
	return snapshot
}

func (s *Server) wpisZarzadzany(ctx context.Context, id string) *schedules.Schedule {
	for _, wpis := range s.czytajHarmonogramy(ctx).Schedules {
		if wpis.Source == schedules.SourceManaged && wpis.ID == id {
			kopia := wpis
			return &kopia
		}
	}
	return nil
}

func (s *Server) wpisZastany(ctx context.Context, id string) *schedules.Schedule {
	for _, wpis := range s.czytajHarmonogramy(ctx).Schedules {
		// Kolizja to plik o dokladnie tej nazwie w /etc/cron.d albo wpis
		// w /etc/crontab z ta sama nazwa. Porownanie po fragmencie sciezki
		// uznaloby "backup" za kolizje z "db-backup-old".
		if wpis.Source != schedules.SourceManaged && wpis.Kind == schedules.KindCron &&
			filepath.Base(wpis.Path) == id {
			kopia := wpis
			return &kopia
		}
	}
	return nil
}

// wyjscieSystemctl uruchamia systemctl z ustalonymi argumentami.
func wyjscieSystemctl(ctx context.Context, args ...string) string {
	cmd := exec.CommandContext(ctx, "/usr/bin/systemctl", args...)
	cmd.Env = []string{"LC_ALL=C", "LANG=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	wyjscie, err := cmd.Output()
	if err != nil {
		return ""
	}
	return string(wyjscie)
}

func odpowiedzHarmonogramow(snapshot schedules.Snapshot, komunikat string) *helperv1.HelperResponse {
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	return &helperv1.HelperResponse{
		Accepted:       true,
		ScheduleResult: &helperv1.ScheduleResult{Snapshot: encoded, Message: komunikat},
	}
}
