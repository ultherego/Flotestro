package helper

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/storage"
)

// Sciezki narzedzi montowania. Stale, a nie szukane w PATH.
const (
	sciezkaMount  = "/usr/bin/mount"
	sciezkaUmount = "/usr/bin/umount"
	sciezkaFsck   = "/usr/sbin/fsck"
	sciezkaBlkid  = "/usr/sbin/blkid"
)

// applyStorage obsluguje operacje na przestrzeni dyskowej hosta.
func (s *Server) applyStorage(ctx context.Context, request *helperv1.HelperRequest,
	action *helperv1.StorageRequest) *helperv1.HelperResponse {
	timeout := time.Duration(request.GetTimeoutSeconds()) * time.Second
	if timeout <= 0 || timeout > 60*time.Minute {
		timeout = 10 * time.Minute
	}
	actionCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	switch action.GetOperation() {
	case helperv1.StorageRequest_OPERATION_READ_LVM:
		return odpowiedzPrzestrzeni(s.czytajLVM(actionCtx), "", "")
	case helperv1.StorageRequest_OPERATION_MOUNT_ENSURE:
		return s.zamontuj(actionCtx, action)
	case helperv1.StorageRequest_OPERATION_MOUNT_REMOVE:
		return s.odmontuj(actionCtx, action)
	case helperv1.StorageRequest_OPERATION_FS_CHECK:
		return s.sprawdzFilesystem(actionCtx, action)
	case helperv1.StorageRequest_OPERATION_LVM_EXTEND:
		return s.rozszerzWolumen(actionCtx, action)
	case helperv1.StorageRequest_OPERATION_FS_RESIZE:
		return s.rozszerzFilesystem(actionCtx, action)
	case helperv1.StorageRequest_OPERATION_FS_CREATE:
		return s.zalozFilesystem(actionCtx, action)
	case helperv1.StorageRequest_OPERATION_DISK_WIPE:
		return s.wyczyscUrzadzenie(actionCtx, action)
	case helperv1.StorageRequest_OPERATION_MOUNT_PLAN:
		return s.zaplanujMontowanie(actionCtx, action)
	case helperv1.StorageRequest_OPERATION_DEVICE_PLAN:
		return s.zaplanujUrzadzenie(actionCtx, action)
	}
	return reject(ErrorUnknownAction, "nieznana operacja na przestrzeni dyskowej")
}

// zaplanujMontowanie liczy roznice miedzy montowaniem zastanym a zadanym.
//
// Niczego nie zmienia. Sprawdzenia wejscia sa te same co przy montowaniu,
// a do tego plan rozwiazuje zrodlo do UUID filesystemu, ktory ten host ma:
// to UUID jedzie potem w zmianie, wiec dysk, ktory po restarcie dostal inna
// sciezke, nie zostanie zamontowany w cudze miejsce.
func (s *Server) zaplanujMontowanie(ctx context.Context, action *helperv1.StorageRequest) *helperv1.HelperResponse {
	if err := storage.WalidujCel(action.GetTarget()); err != nil {
		return reject(ErrorMalformed, err.Error())
	}
	// Plan bez zrodla jest planem odmontowania: montowanie zawsze ma zrodlo,
	// odmontowanie nigdy. Wynik nazywa to wprost polem action.
	odmontowanie := action.GetSource() == ""
	if !odmontowanie {
		if err := storage.WalidujZrodlo(action.GetSource()); err != nil {
			return reject(ErrorMalformed, err.Error())
		}
		if err := storage.WalidujOpcje(action.GetOptions(), action.GetFsType()); err != nil {
			return reject(ErrorMalformed, err.Error())
		}
	}

	stan := s.obrazPrzestrzeni(ctx)
	if stan.UnavailableReason != "" {
		return reject(ErrorUnsupported, stan.UnavailableReason)
	}
	mountinfo, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return reject(ErrorExecFailed, "mountinfo: "+err.Error())
	}
	fstab, _ := os.ReadFile(storage.SciezkaFstab)
	stan.Mounts = storage.PolaczMontowania(
		storage.ParsujMountinfo(string(mountinfo)), storage.ParsujFstab(string(fstab)))

	var plan storage.MountPlan
	if odmontowanie {
		plan = storage.ZaplanujOdmontowanie(stan, action.GetTarget())
		if plan.Action == storage.PlanUsuwa {
			// Odmontowanie zajetego filesystemu sie nie powiedzie; lepiej
			// powiedziec to w planie niz na polowie floty przy wykonaniu.
			if uzytkownicy := s.procesyNaFilesystemie(ctx, action.GetTarget()); uzytkownicy != "" {
				plan.Odmow("filesystem jest w uzyciu przez: " + uzytkownicy)
			}
		}
	} else {
		plan = storage.ZaplanujMontowanie(stan, action.GetSource(), action.GetTarget(),
			action.GetFsType(), action.GetOptions(), action.GetPersist())
	}
	// Plan liczony w prywatnej przestrzeni montowan opisywalby zmiane, ktora
	// na host nigdy nie wejdzie. Odmowa ma stanac w planie, nie w wykonaniu.
	if plan.Refusal == "" && plan.Action != storage.PlanBezZmian &&
		plan.Action != storage.PlanJuzUsuniety {
		if err := wspolnaPrzestrzenMontowan(); err != nil {
			plan.Odmow(err.Error())
		}
	}

	zakodowany, err := json.Marshal(plan)
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	odpowiedz := odpowiedzPrzestrzeni(stan, opisPlanuMontowania(plan), "")
	if odpowiedz.GetStorageResult() != nil {
		odpowiedz.StorageResult.Plan = zakodowany
	}
	return odpowiedz
}

// opisPlanuMontowania streszcza plan jednym zdaniem dla dziennika operacji.
func opisPlanuMontowania(plan storage.MountPlan) string {
	if plan.Refusal != "" {
		return "zmiana nie wejdzie na ten host: " + plan.Refusal
	}
	switch plan.Action {
	case storage.PlanBezZmian:
		return "montowanie jest juz w stanie docelowym"
	case storage.PlanTworzy:
		return "montowanie powstanie ze zrodla " + plan.ResolvedSource
	case storage.PlanJuzUsuniety:
		return "montowania nie ma, wiec nie ma czego usuwac"
	case storage.PlanUsuwa:
		return "montowanie zostanie usuniete"
	default:
		return "zmieni sie: " + strings.Join(plan.Changes, ", ")
	}
}

// zamontuj zaklada wpis w fstab i montuje filesystem.
//
// Kolejnosc jest wazna: najpierw wpis, potem montowanie. Odwrotna zostawialaby
// host, ktory dziala teraz, ale po restarcie wstaje bez tego filesystemu -
// a to jest awaria, ktora ujawnia sie w najgorszym momencie.
func (s *Server) zamontuj(ctx context.Context, action *helperv1.StorageRequest) *helperv1.HelperResponse {
	if err := storage.WalidujZrodlo(action.GetSource()); err != nil {
		return reject(ErrorMalformed, err.Error())
	}
	if err := storage.WalidujCel(action.GetTarget()); err != nil {
		return reject(ErrorMalformed, err.Error())
	}
	if err := storage.WalidujOpcje(action.GetOptions(), action.GetFsType()); err != nil {
		return reject(ErrorMalformed, err.Error())
	}

	if err := wspolnaPrzestrzenMontowan(); err != nil {
		return reject(ErrorUnsupported, err.Error())
	}

	// Filesystem, ktorego host nie widzi, nie da sie zamontowac - i lepiej
	// powiedziec to teraz niz zostawic w fstab wpis, ktory zatrzyma restart.
	if err := s.sprawdzIstnienieZrodla(ctx, action.GetSource()); err != nil {
		return reject(ErrorUnsupported, err.Error())
	}

	if err := zapewnijKatalog(action.GetTarget()); err != nil {
		return reject(ErrorExecFailed, err.Error())
	}

	if action.GetPersist() {
		if err := storage.ZapiszWpisFstab(storage.SciezkaFstab, action.GetSource(),
			action.GetTarget(), action.GetFsType(), action.GetOptions()); err != nil {
			return reject(ErrorExecFailed, "zapis fstab: "+err.Error())
		}
	}

	wyjscie, err := uruchomNarzedzie(ctx, []string{sciezkaMount, action.GetTarget()})
	if err != nil {
		// Wpis, ktory nie daje sie zamontowac teraz, zatrzymalby host przy
		// restarcie. Cofamy go razem z nieudanym montowaniem.
		if action.GetPersist() {
			_ = storage.UsunWpisFstab(storage.SciezkaFstab, action.GetTarget())
		}
		return reject(ErrorExecFailed, "montowanie: "+err.Error()+": "+wyjscie)
	}

	komunikat := action.GetTarget() + " zamontowany"
	if !action.GetPersist() {
		komunikat += "; bez wpisu w fstab zniknie po restarcie"
	}
	return odpowiedzPrzestrzeni(s.czytajLVM(ctx), komunikat, "")
}

// odmontuj usuwa montowanie i wpis panelu.
func (s *Server) odmontuj(ctx context.Context, action *helperv1.StorageRequest) *helperv1.HelperResponse {
	if err := storage.WalidujCel(action.GetTarget()); err != nil {
		return reject(ErrorMalformed, err.Error())
	}
	if err := wspolnaPrzestrzenMontowan(); err != nil {
		return reject(ErrorUnsupported, err.Error())
	}
	// Odmontowanie zajetego filesystemu nie powiedzie sie, a komunikat
	// samego umount nie mowi, kto go trzyma.
	if uzytkownicy := s.procesyNaFilesystemie(ctx, action.GetTarget()); uzytkownicy != "" {
		return reject(ErrorUnsupported,
			"filesystem jest w uzyciu przez: "+uzytkownicy)
	}
	wyjscie, err := uruchomNarzedzie(ctx, []string{sciezkaUmount, action.GetTarget()})
	if err != nil {
		return reject(ErrorExecFailed, "odmontowanie: "+err.Error()+": "+wyjscie)
	}
	if err := storage.UsunWpisFstab(storage.SciezkaFstab, action.GetTarget()); err != nil {
		return reject(ErrorExecFailed, "zapis fstab: "+err.Error())
	}
	return odpowiedzPrzestrzeni(s.czytajLVM(ctx), action.GetTarget()+" odmontowany", "")
}

// sprawdzFilesystem uruchamia fsck na niezamontowanym filesystemie.
func (s *Server) sprawdzFilesystem(ctx context.Context, action *helperv1.StorageRequest) *helperv1.HelperResponse {
	urzadzenie := action.GetDevice()
	if err := storage.WalidujZrodlo(urzadzenie); err != nil {
		return reject(ErrorMalformed, err.Error())
	}
	if odpowiedz := s.sprawdzOdciskPlanuUrzadzenia(ctx, action); odpowiedz != nil {
		return odpowiedz
	}
	// fsck na zamontowanym filesystemie potrafi go uszkodzic. To nie jest
	// ostrzezenie, tylko powod odmowy.
	if punkt := s.punktMontowania(ctx, urzadzenie); punkt != "" {
		return reject(ErrorUnsupported,
			"filesystem jest zamontowany w "+punkt+"; sprawdzenie wymaga odmontowania")
	}

	argumenty := []string{sciezkaFsck, "-n", urzadzenie}
	if action.GetRepair() {
		// Naprawa wymaga zgody na kazde pytanie z gory: interakcji nie ma
		// komu obsluzyc, a fsck czekajacy na odpowiedz wisi do timeoutu.
		argumenty = []string{sciezkaFsck, "-y", urzadzenie}
	}
	wyjscie, err := uruchomNarzedzie(ctx, argumenty)
	komunikat := "filesystem sprawdzony bez bledow"
	if err != nil {
		// fsck zwraca kody bitowe: 1 oznacza poprawione bledy, 4 bledy
		// pozostawione. Kod niezerowy nie zawsze znaczy awarie operacji,
		// wiec wynik opisujemy trescia, a nie samym kodem.
		komunikat = "fsck zglosil uwagi: " + err.Error()
	}
	odpowiedz := odpowiedzPrzestrzeni(s.czytajLVM(ctx), komunikat, wyjscie)
	return odpowiedz
}

// rozszerzWolumen powieksza wolumen logiczny razem z filesystemem.
func (s *Server) rozszerzWolumen(ctx context.Context, action *helperv1.StorageRequest) *helperv1.HelperResponse {
	if !exists(storage.SciezkaLVExtend) {
		return reject(ErrorUnsupported, "ten host nie ma narzedzi LVM")
	}
	argumenty, err := storage.ArgumentyRozszerzeniaLV(action.GetDevice(), action.GetSize(), true)
	if err != nil {
		return reject(ErrorMalformed, err.Error())
	}
	if odpowiedz := s.sprawdzOdciskPlanuUrzadzenia(ctx, action); odpowiedz != nil {
		return odpowiedz
	}
	// Grupa bez wolnego miejsca nie powiekszy zadnego wolumenu. Lepiej
	// powiedziec to teraz niz zostawic operatorowi blad lvextend.
	if powod := s.brakMiejscaWGrupie(ctx, action.GetDevice()); powod != "" {
		return reject(ErrorPreconditionFailed, powod)
	}
	wyjscie, err := uruchomNarzedzie(ctx, argumenty)
	if err != nil {
		return reject(ErrorExecFailed, err.Error()+": "+wyjscie)
	}
	return odpowiedzPrzestrzeni(s.czytajLVM(ctx), "wolumen rozszerzony", wyjscie)
}

// rozszerzFilesystem powieksza filesystem do rozmiaru urzadzenia.
func (s *Server) rozszerzFilesystem(ctx context.Context, action *helperv1.StorageRequest) *helperv1.HelperResponse {
	if odpowiedz := s.sprawdzOdciskPlanuUrzadzenia(ctx, action); odpowiedz != nil {
		return odpowiedz
	}
	stan := s.obrazPrzestrzeni(ctx)
	urzadzenie := stan.Urzadzenie(action.GetDevice())
	if err := (storage.TozsamoscUrzadzenia{
		Path:      action.GetDevice(),
		Serial:    action.GetExpectedSerial(),
		UUID:      action.GetExpectedUuid(),
		SizeBytes: action.GetExpectedSizeBytes(),
	}).Zgadza(urzadzenie); err != nil {
		return reject(ErrorPreconditionFailed, err.Error())
	}
	punkt := ""
	if len(urzadzenie.Mountpoints) > 0 {
		punkt = urzadzenie.Mountpoints[0]
	}
	argumenty, err := storage.ArgumentyRozszerzeniaFS(action.GetDevice(), urzadzenie.FSType, punkt)
	if err != nil {
		return reject(ErrorMalformed, err.Error())
	}
	wyjscie, err := uruchomNarzedzie(ctx, argumenty)
	if err != nil {
		return reject(ErrorExecFailed, err.Error()+": "+wyjscie)
	}
	return odpowiedzPrzestrzeni(s.czytajLVM(ctx), "filesystem rozszerzony", wyjscie)
}

// zalozFilesystem formatuje urzadzenie.
//
// To jest operacja, po ktorej dane sa nie do odzyskania, wiec host sprawdza
// wszystko, co panel podal: tozsamosc urzadzenia i to, czy cokolwiek na nim
// stoi. Zgoda operatora zostala juz zebrana w panelu; tu rozstrzyga fakt.
func (s *Server) zalozFilesystem(ctx context.Context, action *helperv1.StorageRequest) *helperv1.HelperResponse {
	stan := s.obrazPrzestrzeni(ctx)
	if odpowiedz := s.sprawdzCelNiszczacy(stan, action); odpowiedz != nil {
		return odpowiedz
	}
	argumenty, err := storage.ArgumentyFormatowania(action.GetDevice(),
		action.GetFsType(), action.GetLabel())
	if err != nil {
		return reject(ErrorMalformed, err.Error())
	}
	wyjscie, err := uruchomNarzedzie(ctx, argumenty)
	if err != nil {
		return reject(ErrorExecFailed, err.Error()+": "+wyjscie)
	}
	return odpowiedzPrzestrzeni(s.czytajLVM(ctx),
		"filesystem "+action.GetFsType()+" zalozony na "+action.GetDevice(), wyjscie)
}

// wyczyscUrzadzenie usuwa sygnatury filesystemow.
func (s *Server) wyczyscUrzadzenie(ctx context.Context, action *helperv1.StorageRequest) *helperv1.HelperResponse {
	stan := s.obrazPrzestrzeni(ctx)
	if odpowiedz := s.sprawdzCelNiszczacy(stan, action); odpowiedz != nil {
		return odpowiedz
	}
	argumenty, err := storage.ArgumentyCzyszczenia(action.GetDevice())
	if err != nil {
		return reject(ErrorMalformed, err.Error())
	}
	wyjscie, err := uruchomNarzedzie(ctx, argumenty)
	if err != nil {
		return reject(ErrorExecFailed, err.Error()+": "+wyjscie)
	}
	// Dane sa nadal fizycznie na plytach: usunelismy sygnatury, a nie
	// zawartosc. Operator ma to przeczytac, zanim odda dysk komus innemu.
	return odpowiedzPrzestrzeni(s.czytajLVM(ctx),
		"sygnatury filesystemow usuniete z "+action.GetDevice()+
			"; zawartosc nosnika nie zostala nadpisana", wyjscie)
}

// sprawdzCelNiszczacy pilnuje, ze operacja trafi w to urzadzenie, ktore
// operator ogladal, i ze nic na nim nie stoi.
func (s *Server) sprawdzCelNiszczacy(stan storage.Snapshot,
	action *helperv1.StorageRequest) *helperv1.HelperResponse {
	if err := (storage.TozsamoscUrzadzenia{
		Path:      action.GetDevice(),
		Serial:    action.GetExpectedSerial(),
		UUID:      action.GetExpectedUuid(),
		SizeBytes: action.GetExpectedSizeBytes(),
	}).Zgadza(stan.Urzadzenie(action.GetDevice())); err != nil {
		return reject(ErrorPreconditionFailed, err.Error())
	}
	if punkt := storage.WUzyciu(stan, action.GetDevice()); punkt != "" {
		return reject(ErrorUnsupported,
			"urzadzenie jest w uzyciu (zamontowane w "+punkt+"); operacja niszczaca wymaga odmontowania")
	}
	return nil
}

// brakMiejscaWGrupie zwraca powod, gdy grupa wolumenow nie ma juz miejsca.
func (s *Server) brakMiejscaWGrupie(ctx context.Context, wolumen string) string {
	lvm := s.czytajLVM(ctx)
	for _, wpis := range lvm.Volumes {
		if !storage.PasujeWolumen(wpis, wolumen) {
			continue
		}
		for _, grupa := range lvm.Groups {
			if grupa.Name == wpis.Group && grupa.FreeBytes == 0 {
				return "grupa " + grupa.Name + " nie ma wolnego miejsca; " +
					"wolumen nie da sie rozszerzyc bez dolozenia dysku"
			}
		}
	}
	return ""
}

// obrazPrzestrzeni czyta topologie urzadzen po stronie helpera.
func (s *Server) obrazPrzestrzeni(ctx context.Context) storage.Snapshot {
	wyjscie, err := wyjscieNarzedzia(ctx, storage.SciezkaLsblk, "-J", "-b", "-o",
		"NAME,PATH,TYPE,SIZE,FSTYPE,LABEL,UUID,PARTUUID,MOUNTPOINTS,MODEL,SERIAL,WWN,ROTA,RO,PKNAME")
	if err != nil {
		return storage.Snapshot{UnavailableReason: "lsblk: " + err.Error()}
	}
	urzadzenia, err := storage.ParsujUrzadzenia(wyjscie)
	if err != nil {
		return storage.Snapshot{UnavailableReason: err.Error()}
	}
	return storage.Snapshot{Devices: urzadzenia}
}

// zaplanujUrzadzenie liczy plan sprawdzenia albo rozszerzenia bez dotykania
// hosta. Urzadzenie, ktorego nie ma, filesystem zamontowany przed fsck
// i grupa bez miejsca sa odmowa w planie, nie awaria wykonania.
func (s *Server) zaplanujUrzadzenie(ctx context.Context, action *helperv1.StorageRequest) *helperv1.HelperResponse {
	stan := s.stanUrzadzen(ctx)
	plan := planUrzadzenia(stan, action)
	zakodowany, err := json.Marshal(plan)
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	komunikat := "zmiana nie wejdzie na ten host: " + plan.Refusal
	if plan.Refusal == "" {
		komunikat = strings.Join(plan.Changes, "; ")
	}
	odpowiedz := odpowiedzPrzestrzeni(stan, komunikat, "")
	if odpowiedz.GetStorageResult() != nil {
		odpowiedz.StorageResult.Plan = zakodowany
	}
	return odpowiedz
}

// planUrzadzenia liczy plan wedlug rodzaju nazwanego w zleceniu; operacje
// mutujace nazywaja go wprost.
func planUrzadzenia(stan storage.Snapshot, action *helperv1.StorageRequest) storage.DevicePlan {
	rodzaj := action.GetPlan()
	switch action.GetOperation() {
	case helperv1.StorageRequest_OPERATION_FS_CHECK:
		rodzaj = storage.PlanSprawdzenie
	case helperv1.StorageRequest_OPERATION_FS_RESIZE:
		rodzaj = storage.PlanRozszerzenieFS
	case helperv1.StorageRequest_OPERATION_LVM_EXTEND:
		rodzaj = storage.PlanRozszerzenieLV
	}
	switch rodzaj {
	case storage.PlanRozszerzenieFS:
		return storage.ZaplanujRozszerzenieFS(stan, action.GetDevice())
	case storage.PlanRozszerzenieLV:
		return storage.ZaplanujRozszerzenieLV(stan, action.GetDevice(), action.GetSize())
	case storage.PlanSprawdzenie:
		return storage.ZaplanujSprawdzenie(stan, action.GetDevice(), action.GetRepair())
	}
	plan := storage.DevicePlan{Operation: rodzaj, Device: action.GetDevice()}
	plan.Odmow("nieznany rodzaj planu " + rodzaj)
	return plan
}

// sprawdzOdciskPlanuUrzadzenia porownuje plan liczony teraz z tym, na
// ktory operator sie zgodzil. Inny odcisk znaczy, ze urzadzenie albo grupa
// zmienily sie od planowania - i to jest odmowa, nie ostrzezenie.
func (s *Server) sprawdzOdciskPlanuUrzadzenia(ctx context.Context, action *helperv1.StorageRequest) *helperv1.HelperResponse {
	oczekiwany := action.GetPlanHash()
	if oczekiwany == "" {
		return nil
	}
	if teraz := planUrzadzenia(s.stanUrzadzen(ctx), action); teraz.PlanHash != oczekiwany {
		return reject(ErrorPreconditionFailed,
			"urzadzenie "+action.GetDevice()+" zmienilo sie od planowania; zmiana wymaga nowego planu")
	}
	return nil
}

// stanUrzadzen sklada topologie urzadzen razem z LVM.
func (s *Server) stanUrzadzen(ctx context.Context) storage.Snapshot {
	stan := s.obrazPrzestrzeni(ctx)
	lvm := s.czytajLVM(ctx)
	stan.Groups, stan.Volumes = lvm.Groups, lvm.Volumes
	stan.LVMUnavailableReason = lvm.LVMUnavailableReason
	return stan
}

// czytajLVM zbiera grupy i wolumeny logiczne.
func (s *Server) czytajLVM(ctx context.Context) storage.Snapshot {
	snapshot := storage.Snapshot{ObservedAt: time.Now().UTC()}
	if !exists(storage.SciezkaVGS) || !exists(storage.SciezkaLVS) {
		// Host bez LVM to nie host bez odpowiedzi.
		snapshot.LVMUnavailableReason = "this host has no LVM tools (vgs, lvs)"
		return snapshot
	}
	if wyjscie, err := wyjscieNarzedzia(ctx, storage.SciezkaVGS,
		"--reportformat", "json", "--units", "b"); err == nil {
		if grupy, err := storage.ParsujGrupy(wyjscie); err == nil {
			snapshot.Groups = grupy
		}
	}
	if wyjscie, err := wyjscieNarzedzia(ctx, storage.SciezkaLVS,
		"--reportformat", "json", "--units", "b",
		"-o", "lv_name,vg_name,lv_size,lv_path"); err == nil {
		if wolumeny, err := storage.ParsujWolumeny(wyjscie); err == nil {
			snapshot.Volumes = wolumeny
		}
	}
	return snapshot
}

// sprawdzIstnienieZrodla upewnia sie, ze host widzi wskazany filesystem.
func (s *Server) sprawdzIstnienieZrodla(ctx context.Context, zrodlo string) error {
	if strings.HasPrefix(zrodlo, "/dev/") {
		if !exists(zrodlo) {
			return fmt.Errorf("urzadzenie %s nie istnieje na tym hoscie", zrodlo)
		}
		return nil
	}
	if !exists(sciezkaBlkid) {
		// Bez blkid nie potrafimy sprawdzic identyfikatora. Brak sprawdzenia
		// jest tu faktem, a nie zgoda.
		return fmt.Errorf("host nie ma blkid; nie da sie sprawdzic %s przed zapisem do fstab", zrodlo)
	}
	klucz, wartosc, _ := strings.Cut(zrodlo, "=")
	if _, err := wyjscieNarzedzia(ctx, sciezkaBlkid, "-t", klucz+"="+wartosc, "-o", "device"); err != nil {
		return fmt.Errorf("host nie widzi filesystemu %s", zrodlo)
	}
	return nil
}

// punktMontowania zwraca miejsce, w ktorym urzadzenie jest zamontowane.
func (s *Server) punktMontowania(ctx context.Context, urzadzenie string) string {
	wyjscie, err := wyjscieNarzedzia(ctx, storage.SciezkaLsblk, "-J", "-b", "-o",
		"NAME,PATH,TYPE,SIZE,MOUNTPOINTS")
	if err != nil {
		return ""
	}
	urzadzenia, err := storage.ParsujUrzadzenia(wyjscie)
	if err != nil {
		return ""
	}
	for _, wpis := range urzadzenia {
		if wpis.Path == urzadzenie && len(wpis.Mountpoints) > 0 {
			return wpis.Mountpoints[0]
		}
	}
	return ""
}

// procesyNaFilesystemie wymienia procesy trzymajace filesystem.
//
// Sam komunikat "target is busy" nie mowi, kto go trzyma, a to jest jedyna
// informacja, ktorej operator w tym momencie potrzebuje.
func (s *Server) procesyNaFilesystemie(ctx context.Context, cel string) string {
	const sciezkaLsof = "/usr/bin/lsof"
	if !exists(sciezkaLsof) {
		return ""
	}
	wyjscie, err := wyjscieNarzedzia(ctx, sciezkaLsof, "-t", cel)
	if err != nil || strings.TrimSpace(wyjscie) == "" {
		return ""
	}
	pidy := strings.Fields(wyjscie)
	if len(pidy) > 10 {
		pidy = append(pidy[:10], "...")
	}
	return "PID " + strings.Join(pidy, ", ")
}

// wspolnaPrzestrzenMontowan sprawdza, czy helper dzieli przestrzen montowan
// z hostem.
//
// Usluga uruchomiona z PrivateTmp, ProtectSystem albo inna dyrektywa
// tworzaca przestrzen montowan dostaje wlasna kopie drzewa, z ktorej nic
// nie wraca na host. mount konczy sie wtedy sukcesem, helper melduje
// "zamontowany", a host filesystemu nie ma. To jest najgorszy z wynikow:
// cichy. Lepiej odmowic i nazwac powod.
func wspolnaPrzestrzenMontowan() error {
	hosta, err := os.Readlink("/proc/1/ns/mnt")
	if err != nil {
		return fmt.Errorf("przestrzen montowan hosta: %w", err)
	}
	helpera, err := os.Readlink("/proc/self/ns/mnt")
	if err != nil {
		return fmt.Errorf("przestrzen montowan helpera: %w", err)
	}
	if hosta != helpera {
		return fmt.Errorf("helper dziala w prywatnej przestrzeni montowan " +
			"(PrivateTmp albo podobna dyrektywa uslugi); montowanie nie byloby widoczne dla hosta")
	}
	return nil
}

func zapewnijKatalog(cel string) error {
	if exists(cel) {
		return nil
	}
	cmd := exec.Command("/usr/bin/mkdir", "-p", cel)
	cmd.Env = srodowiskoNarzedzi()
	if wyjscie, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("katalog %s: %w: %s", cel, err, strings.TrimSpace(string(wyjscie)))
	}
	return nil
}

func odpowiedzPrzestrzeni(snapshot storage.Snapshot, komunikat, wyjscie string) *helperv1.HelperResponse {
	zakodowane, err := json.Marshal(snapshot)
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	return &helperv1.HelperResponse{
		Accepted: true,
		StorageResult: &helperv1.StorageResult{
			Snapshot: zakodowane, Message: komunikat, Output: wyjscie,
		},
	}
}
