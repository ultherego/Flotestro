import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Job } from "../../lib/types";
import { Czas, Pusto } from "../../components/ui";
import { bytes } from "../../lib/format";
import { SwiezoscModulu, useHost, useModul } from "./wspolne";
import { PotwierdzenieCelu } from "./PotwierdzenieCelu";

type Urzadzenie = {
  name: string;
  path: string;
  type: string;
  size_bytes: number;
  fs_type?: string;
  label?: string;
  uuid?: string;
  model?: string;
  serial?: string;
  parent?: string;
  rotational?: boolean;
  read_only: boolean;
  mountpoints?: string[];
  fs_size_bytes?: number;
  fs_used_bytes?: number;
};

type Montowanie = {
  target: string;
  source: string;
  fs_type: string;
  options?: string;
  fstab_options?: string;
  in_fstab: boolean;
  mounted: boolean;
  managed: boolean;
  used_percent?: number;
  inodes_used_percent?: number;
  size_bytes?: number;
  avail_bytes?: number;
};

type Snapshot = {
  devices?: Urzadzenie[];
  mounts?: Montowanie[];
  groups?: { name: string; size_bytes: number; free_bytes: number; lv_count: number }[];
  volumes?: { name: string; group: string; path: string; size_bytes: number }[];
  lvm_unavailable_reason?: string;
  raid_unavailable_reason?: string;
  observed_at?: string;
  unavailable_reason?: string;
};

type Zamiar = { akcja: string; etykieta: string; opis: string; payload: Record<string, unknown> };

/**
 * Przestrzen dyskowa hosta.
 *
 * Panel pokazuje stan jadra i tresc fstab osobno: plik mowi, co ma byc
 * zamontowane po restarcie, a nie co jest zamontowane teraz. Roznica miedzy
 * jednym a drugim jest zwykle powodem, dla ktorego ktos otwiera te zakladke.
 */
export function Przestrzen() {
  const host = useHost();
  const queryClient = useQueryClient();
  const modul = useModul<Snapshot>(host.id, "storage");
  const [zamiar, setZamiar] = useState<Zamiar | null>(null);
  const [komunikat, setKomunikat] = useState("");
  const [kreator, setKreator] = useState(false);

  const zlec = useMutation({
    mutationFn: (tresc: Record<string, unknown>) =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, tresc),
    onSuccess: (zadanie) => {
      setKomunikat(
        zadanie.requires_approval
          ? `Job ${zadanie.id.slice(0, 8)} is waiting for approval.`
          : `Job ${zadanie.id.slice(0, 8)} has been queued.`,
      );
      setZamiar(null);
      setKreator(false);
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
    onError: (error) => setKomunikat(error instanceof Error ? error.message : String(error)),
  });

  const snapshot = modul.data?.payload;
  if (!modul.data) return <Pusto>This host has not reported its storage yet.</Pusto>;

  return (
    <>
      <p className="podtytul">
        Devices from the kernel, mounts from mountinfo, persistence from fstab —
        kept apart on purpose: the file says what should be mounted after a
        reboot, not what is mounted now.
      </p>

      {snapshot?.unavailable_reason && (
        <p className="ostrzezenie">
          <span>Storage state could not be read: {snapshot.unavailable_reason}</span>
        </p>
      )}

      <div className="filtry">
        <button
          onClick={() => zlec.mutate({ action: "storage.plan", payload: { storage: {} } })}
          disabled={zlec.isPending || host.connection_state !== "online"}
        >
          Read from host
        </button>
        <button className="wtorny" onClick={() => setKreator((otwarty) => !otwarty)}>
          {kreator ? "Cancel" : "Mount a filesystem"}
        </button>
      </div>

      {komunikat && <p className="zrodlo" style={{ marginBottom: 12 }}>{komunikat}</p>}
      {kreator && <KreatorMontowania onZamiar={setZamiar} />}

      <h2>Mounts</h2>
      <table>
        <thead>
          <tr>
            <th>Mount point</th><th>Source</th><th>Type</th><th>State</th>
            <th>Space used</th><th>Inodes used</th><th>Owner</th><th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {(snapshot?.mounts ?? []).map((montowanie) => (
            <tr key={montowanie.target}>
              <td>{montowanie.target}</td>
              <td title={montowanie.source}>{montowanie.source.slice(0, 40)}</td>
              <td>{montowanie.fs_type}</td>
              {/* Cztery kombinacje "zamontowany / w fstab" znacza cztery rozne
                  rzeczy i wszystkie sa dla operatora wazne. */}
              <td>
                {montowanie.mounted && montowanie.in_fstab && "mounted, persistent"}
                {montowanie.mounted && !montowanie.in_fstab && (
                  <span className="znacznik nieznany">mounted, gone after reboot</span>
                )}
                {!montowanie.mounted && montowanie.in_fstab && (
                  <span className="znacznik nieznany">in fstab, not mounted</span>
                )}
              </td>
              {/* Nieznana zajetosc zostaje nieznana: filesystem sieciowy
                  potrafi nie podac liczby i-wezlow wcale. */}
              <td>
                {montowanie.used_percent === undefined ? (
                  <span className="znacznik nieznany">unknown</span>
                ) : (
                  <>
                    {montowanie.used_percent}%
                    {montowanie.size_bytes !== undefined && (
                      <span className="zrodlo"> of {bytes(montowanie.size_bytes)}</span>
                    )}
                  </>
                )}
              </td>
              <td>
                {montowanie.inodes_used_percent === undefined ? (
                  <span className="znacznik nieznany">unknown</span>
                ) : (
                  `${montowanie.inodes_used_percent}%`
                )}
              </td>
              <td>{montowanie.managed ? "Flotestro" : <span className="znacznik nieznany">host admin</span>}</td>
              <td>
                {montowanie.managed && montowanie.mounted && (
                  <button
                    className="wtorny"
                    onClick={() =>
                      setZamiar({
                        akcja: "mount.remove",
                        etykieta: "Unmount",
                        opis: `${montowanie.target} will be unmounted and its fstab entry removed. Processes holding it are checked first.`,
                        payload: { storage: { target: montowanie.target } },
                      })
                    }
                  >
                    Unmount
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      <h2>Devices</h2>
      <table>
        <thead>
          <tr><th>Device</th><th>Type</th><th>Size</th><th>Filesystem</th><th>Mounted at</th><th>Identity</th><th>Actions</th></tr>
        </thead>
        <tbody>
          {(snapshot?.devices ?? []).map((urzadzenie) => (
            <tr key={urzadzenie.path}>
              {/* Wciecie oddaje topologie dysk -> partycja -> wolumen. */}
              <td style={{ paddingLeft: urzadzenie.parent ? 24 : undefined }}>
                {urzadzenie.path}
                {urzadzenie.read_only && <span className="znacznik"> read-only</span>}
              </td>
              <td>{urzadzenie.type}</td>
              <td>{bytes(urzadzenie.size_bytes)}</td>
              <td>
                {urzadzenie.fs_type || "—"}
                {urzadzenie.fs_size_bytes !== undefined && urzadzenie.fs_size_bytes < urzadzenie.size_bytes && (
                  <span className="zrodlo"> · fs {bytes(urzadzenie.fs_size_bytes)}</span>
                )}
              </td>
              <td>{(urzadzenie.mountpoints ?? []).join(", ") || "—"}</td>
              {/* Identyfikacja idzie po UUID i serialu: /dev/sdX zalezy od
                  kolejnosci wykrywania i po restarcie wskazuje inny dysk. */}
              <td className="zrodlo">
                {urzadzenie.uuid ? `UUID=${urzadzenie.uuid.slice(0, 13)}…` : ""}
                {urzadzenie.serial ? ` ${urzadzenie.model ?? ""} ${urzadzenie.serial}` : ""}
                {!urzadzenie.uuid && !urzadzenie.serial && "—"}
              </td>
              <td>
                {/* Operacje na urzadzeniu maja sens tylko wtedy, gdy nic
                    na nim nie stoi - i host i tak to sprawdzi jeszcze raz. */}
                {(urzadzenie.mountpoints ?? []).length === 0 && (
                  <div className="operacje">
                    {urzadzenie.fs_type && (
                      <button
                        onClick={() =>
                          setZamiar({
                            akcja: "filesystem.check",
                            etykieta: "Check filesystem",
                            opis: `${urzadzenie.path} will be checked read-only. The check refuses to run if the filesystem is mounted.`,
                            payload: { storage: { device: urzadzenie.path } },
                          })
                        }
                      >
                        Check
                      </button>
                    )}
                    {urzadzenie.fs_type && (
                      <button
                        onClick={() =>
                          setZamiar({
                            akcja: "filesystem.resize",
                            etykieta: "Grow filesystem",
                            opis: `The filesystem on ${urzadzenie.path} will grow to fill the device (${bytes(urzadzenie.size_bytes)}).`,
                            payload: { storage: tozsamosc(urzadzenie) },
                          })
                        }
                      >
                        Grow
                      </button>
                    )}
                    {/* Formatowanie i czyszczenie niosa tozsamosc urzadzenia
                        z tego wiersza: host odmowi, jesli trafi w co innego. */}
                    <button
                      className="wtorny"
                      onClick={() =>
                        setZamiar({
                          akcja: "filesystem.create",
                          etykieta: "Format device",
                          opis: `Everything on ${urzadzenie.path} (${bytes(urzadzenie.size_bytes)}${
                            urzadzenie.serial ? `, serial ${urzadzenie.serial}` : ""
                          }) will be destroyed and a new ext4 filesystem created. This needs two approvals.`,
                          payload: {
                            storage: { ...tozsamosc(urzadzenie), fs_type: "ext4" },
                          },
                        })
                      }
                    >
                      Format
                    </button>
                    <button
                      className="wtorny"
                      onClick={() =>
                        setZamiar({
                          akcja: "disk.wipe",
                          etykieta: "Wipe signatures",
                          opis: `Filesystem signatures on ${urzadzenie.path} will be removed, so the host stops recognising what is on it. The contents are not overwritten. This needs two approvals.`,
                          payload: { storage: tozsamosc(urzadzenie) },
                        })
                      }
                    >
                      Wipe
                    </button>
                  </div>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      <h2>Volume groups</h2>
      {snapshot?.lvm_unavailable_reason ? (
        <Pusto>{snapshot.lvm_unavailable_reason}</Pusto>
      ) : !snapshot?.groups?.length ? (
        <Pusto>This host has LVM but no volume groups.</Pusto>
      ) : (
        <table>
          <thead><tr><th>Group</th><th>Size</th><th>Free</th><th>Volumes</th></tr></thead>
          <tbody>
            {snapshot.groups.map((grupa) => (
              <tr key={grupa.name}>
                <td>{grupa.name}</td>
                <td>{bytes(grupa.size_bytes)}</td>
                {/* Zero wolnego miejsca rozstrzyga o tym, czy da sie
                    cokolwiek rozszerzyc - i jest liczba, nie brakiem. */}
                <td>{bytes(grupa.free_bytes)}</td>
                <td>{grupa.lv_count}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {snapshot?.volumes?.length ? (
        <table>
          <thead><tr><th>Logical volume</th><th>Group</th><th>Size</th><th>Actions</th></tr></thead>
          <tbody>
            {snapshot.volumes.map((wolumen) => (
              <tr key={wolumen.path}>
                <td>{wolumen.path}</td>
                <td>{wolumen.group}</td>
                <td>{bytes(wolumen.size_bytes)}</td>
                <td>
                  {/* Rozszerzamy wylacznie w gore i razem z filesystemem:
                      wolumen wiekszy od filesystemu nie daje ani bajta. */}
                  <button
                    onClick={() =>
                      setZamiar({
                        akcja: "lvm.extend",
                        etykieta: "Extend volume",
                        opis: `${wolumen.path} will grow by 512M together with its filesystem, if the group has room.`,
                        payload: { storage: { device: wolumen.path, size: "+512M" } },
                      })
                    }
                  >
                    Extend by 512M
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}

      {snapshot?.raid_unavailable_reason && (
        <p className="zrodlo">{snapshot.raid_unavailable_reason}</p>
      )}

      <SwiezoscModulu fragment={modul.data} />
      {snapshot?.observed_at && (
        <p className="zrodlo">
          Storage read <Czas wartosc={snapshot.observed_at} />
        </p>
      )}

      {zamiar && (
        <PotwierdzenieCelu
          host={host}
          etykieta={zamiar.etykieta}
          opis={zamiar.opis}
          pracuje={zlec.isPending}
          onPotwierdz={(powod, potwierdzenie) =>
            zlec.mutate({
              action: zamiar.akcja,
              reason: powod,
              // Operacja niszczaca wymaga przepisanej nazwy celu. Reszta
              // operacji jej nie potrzebuje, ale wyslana nie przeszkadza.
              target_confirmation: potwierdzenie,
              payload: zamiar.payload,
            })
          }
          onAnuluj={() => setZamiar(null)}
        />
      )}
    </>
  );
}

/**
 * Tozsamosc urzadzenia wysylana razem z operacja. Host porownuje ja ze swoim
 * stanem i odmawia przy pierwszej niezgodnosci: /dev/sdX po restarcie potrafi
 * wskazac inny dysk niz ten, ktory operator wlasnie oglada.
 */
function tozsamosc(urzadzenie: Urzadzenie): Record<string, unknown> {
  return {
    device: urzadzenie.path,
    expected_serial: urzadzenie.serial ?? "",
    expected_size_bytes: urzadzenie.size_bytes,
    expected_uuid: urzadzenie.uuid ?? "",
  };
}

/**
 * Kreator montowania. Zrodlo podajemy identyfikatorem trwalym, bo nazwa
 * /dev/sdX zalezy od kolejnosci wykrywania i po restarcie potrafi wskazac
 * inny dysk.
 */
function KreatorMontowania({ onZamiar }: { onZamiar: (zamiar: Zamiar) => void }) {
  const [zrodlo, setZrodlo] = useState("");
  const [cel, setCel] = useState("");
  const [typ, setTyp] = useState("ext4");
  const [opcje, setOpcje] = useState("defaults,nofail");
  const [trwale, setTrwale] = useState(true);

  return (
    <div className="formularz" style={{ marginBottom: 16 }}>
      <h2>Mount a filesystem</h2>
      <div className="filtry">
        <input
          value={zrodlo}
          onChange={(e) => setZrodlo(e.target.value)}
          placeholder="UUID=… or /dev/mapper/…"
          style={{ minWidth: 300 }}
        />
        <input value={cel} onChange={(e) => setCel(e.target.value)} placeholder="Mount point, e.g. /mnt/dane" />
        <input value={typ} onChange={(e) => setTyp(e.target.value)} placeholder="Filesystem type" style={{ width: 120 }} />
        <input value={opcje} onChange={(e) => setOpcje(e.target.value)} placeholder="Options" />
      </div>
      {/* Bez wpisu w fstab montowanie zniknie po restarcie; operator ma o tym
          wiedziec przed, a nie po awarii. */}
      <label className="przelacznik">
        <input type="checkbox" checked={trwale} onChange={(e) => setTrwale(e.target.checked)} />
        Keep it after reboot (write an fstab entry)
      </label>
      <button
        onClick={() =>
          onZamiar({
            akcja: "mount.ensure",
            etykieta: "Mount filesystem",
            opis: `${zrodlo} will be mounted at ${cel} as ${typ}${
              trwale ? " and written to fstab" : " for this boot only"
            }.`,
            payload: {
              storage: { source: zrodlo, target: cel, fs_type: typ, options: opcje, persist: trwale },
            },
          })
        }
        disabled={!zrodlo || !cel || !typ}
      >
        Mount
      </button>
    </div>
  );
}
