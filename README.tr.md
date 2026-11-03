# CorOS v1.0

[![Lisans](https://img.shields.io/github/license/corpusproject/CorOS?label=license)](LICENSE)
[![Dil](https://img.shields.io/badge/language-Rust-orange?logo=rust)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/platform-x86__64%20UEFI-blue)](#)
[![Durum](https://img.shields.io/badge/status-research%20%2F%20hobby-lightgrey)](#bilinen-sınırlamalar)

*Corpus Studio tarafından geliştirilen deneysel bir işletim sistemi projesi.*

[English](README.md) · **Türkçe**

![CorOS duvar kâğıdı önizlemesi — çalışan masaüstünün ekran görüntüsü değildir](assets/wallpapers/wallpaper.png)

CorOS, saf `#![no_std]` Rust ile yazılmış, harici crate bağımlılığı olmayan,
x86_64 **UEFI** işletim sistemi projesidir. Kendi UEFI yükleyicisi **CorBoot**,
**CorKernel** çekirdeğini yükler. Çekirdek framebuffer tabanlı masaüstü ve PS/2
klavye/fare girdisi sağlar.

> **Durum: v1.0 — araştırma / hobi işletim sistemi.** CorOS, UEFI ile VirtualBox'ta
> açılır. Linux'un yerine geçmez ve gerçek donanımda doğrulanmamıştır. Özellik
> açıklamalarını değerlendirirken [bilinen sınırlamaları](#bilinen-sınırlamalar) okuyun.

## Hızlı başlangıç

Windows'ta Rust stable ve Python 3 kurun; ardından PowerShell'de çalıştırın. UEFI
hedefini bir kez kurmanız gerekebilir: `rustup target add x86_64-unknown-uefi`.

```powershell
powershell -ExecutionPolicy Bypass -File tools/build.ps1 -StageEfiFiles
powershell -ExecutionPolicy Bypass -File tools/run-vbox.ps1 -Iso
```

Hibrit ISO üretmek için derleme komutuna `-MakeIso` ekleyin. ISO yaklaşık 2,2 GB'tır;
ESP dışındaki içeriğin çoğu yer tutucudur (ayrıntılar için sınırlamalara bakın).

## Özellikler

| Alan | Projede bulunanlar |
|------|-------------------|
| **Açılış ve çekirdek** | CorBoot UEFI yükleyicisi, çekirdek/initrd yükleme, bellek haritası yönetimi, BootInfo aktarımı; CorKernel GDT/IDT/TSS, frame allocator, heap, PIC + Local APIC, PIT/TSC zamanlama, seri günlükleyici ve 361 girişli Linux tarzı sistem çağrısı tablosu (`SYSCALL`/`SYSRET`). |
| **Girdi** | Genişletilmiş scancode'lar, ok tuşları, Delete ve Super desteğine sahip kilitsiz PS/2 klavye ring buffer'ı; kendini yeniden eşitleyen ve hızlandırmalı PS/2 fare durum makinesi. |
| **Masaüstü** | Pencere yöneticisi, dosya gezgini, terminal, not defteri, hesap makinesi, çizim, kod düzenleyici, ayarlar, aygıt yöneticisi, disk yöneticisi, kilit ekranı ve daha fazlası. |
| **Sistem araçları** | Çekirdek başına CPU geçmiş grafikleri, bellek dökümü ve süreç tablosu sunan Görev Yöneticisi; çalma listesi, ses düzeyi/konum kontrolü, ekolayzır görselleştiricisi ve AC'97 tetikleyicili CorAudio. |
| **Ağ arayüzü** | Hex inceleyici ve güvenlik duvarı kuralı anahtarları içeren, paket yakalama tarzı CorShark tablosu. |
| **Alt sistem crate'leri** | `subsystems/` altında 22 bağımsız `no_std` crate; `corsyscall`, `corvfs`, `cornet`, `cormm`, `corsched`, `corsec`, `coripc`, `cortoolchain` (ELF dinamik bağlayıcı/relocation), `corvirt`, `cordrm`, `corblock` ve `corwifi` dahil. |
| **Linux özellik çalışmaları (1–3. kilometre taşları)** | Namespace/chroot, cgroups v2, POSIX sinyalleri, futex/eşzamanlama ilkelleri, swap/LRU sayfalama, `AF_UNIX` + `SCM_RIGHTS`, FIFO'lar, POSIX mesaj kuyrukları, AMD64 relocation destekli `ld.so` tarzı yükleyici ve Btrfs / ZFS / F2FS / XFS / ISO9660 (Rock Ridge + Joliet) disk biçimi ayrıştırıcıları. Doğrulanmamış ayrıştırıcı düzeltmeleri için [bilinen sınırlamalara](#bilinen-sınırlamalar) bakın. |

## Depo yapısı

| Yol | Amaç |
|-----|------|
| `boot/corboot` | UEFI yükleyicisi |
| `shared/corboot-info` | Yükleyici ve çekirdek arasında sürümlü boot ABI'si |
| `kernel/corkernel` | Çekirdek, sürücüler, pencere yöneticisi, dosya sistemleri (`src/fs`) |
| `subsystems/*` | Bağımsız `no_std` alt sistem crate'leri |
| `tests/e2e` | Python E2E model testleri (590 test) |
| `tests/*.py` | Adversarial/ampirik sınayıcı betikleri |
| `tests/empirical_harness` | Bağımsız UEFI test uygulaması (kendi Cargo projesi) |
| `tools/` | Derleme, ISO (`make-iso.py`) ve VirtualBox araçları |
| `docs/` | Açılış, bellek, kesmeler ve araç zinciri üzerine erken tasarım notları |
| `assets/` | İkonlar, yazı tipleri ve duvar kâğıtları |

## Derleme ve test

Gereksinimler: Rust stable (`rust-toolchain.toml` dosyasına bakın),
`x86_64-unknown-uefi` hedefi, Windows PowerShell ve Python 3.

```powershell
# Çalışma alanını tür denetiminden geçir
cargo check --workspace --target x86_64-unknown-uefi

# Derle ve EFI System Partition dosyalarını hazırla
powershell -ExecutionPolicy Bypass -File tools/build.ps1 -StageEfiFiles

# E2E model testlerini çalıştır (çekirdeği çalıştırmaz)
py -3 tests/e2e/run_e2e_tests.py
```

VirtualBox'ta çalıştırmak için `powershell -ExecutionPolicy Bypass -File tools/run-vbox.ps1 -Iso`
komutunu kullanın. Fareyi yakalamak için VM penceresine tıklayın; bırakmak için
**Right Ctrl** (Host Key) tuşuna basın. Seri çıktısı `outputs/serial.log` dosyasına yazılır.

## Bilinen sınırlamalar

- **Ölçek:** Kaynak kod yaklaşık 150 bin Rust satırı (≈620 dosya) içeriyor. On milyonlarca satıra ulaşma gibi önceki hedefler gerçekleşmedi ve bu yönde bir iddia yok.
- **ISO içeriği:** `dist/coros.iso`, `tools/make-iso.py` büyük *yer tutucu* veriler (`/LIVE/ROOTFS.IMG`, `/POOL/PACKAGES.DAT`, …) yazdığı için yaklaşık 2,2 GB'tır. Yalnızca içindeki 64 MB ESP imajı gerçekten açılışta kullanılır; geri kalanı çalışan bir paket seti veya kök dosya sistemi değildir.
- **Testler:** `tests/e2e`, çekirdeği çalıştıran testler değil, amaçlanan davranışın Python modelleri/spesifikasyonlarıdır. Gerçek açılış VirtualBox'ta elle doğrulanır.
- **Donanım desteği:** Aygıt/yonga seti veritabanları veri tablolarıdır. Geniş gerçek donanım sürücü desteği (tüm CPU/GPU/NIC/depolama aygıtları) **uygulanmamıştır**.
- **Web tarayıcısı:** Depodaki `CorBrowse` penceresi basit bir makettir; yerine ayrı bir tarayıcı projesi planlanmaktadır.
- **3. kilometre taşı incelemesi:** Bir incelemede Btrfs/ZFS ayrıştırıcıları için altı düzeltme istendi (çift Btrfs magic, uberblock TXG offset'leri, `parse_znode_bonus` sınırları, Micro-ZAP endian düzeni, iç düğüm anahtar karşılaştırması ve çok seviyeli dizin çözümleme). Çalışma yarıda kesildi; tamamlandıkları **doğrulanmadı**.
- **Başlanmadı:** xHCI/EHCI USB yığını, Netfilter/conntrack/NAT ve KVM/VMX/SVM hypervisor desteği (planlanan 4. kilometre taşı).

## Lisans

MIT — [LICENSE](LICENSE) dosyasına bakın.
