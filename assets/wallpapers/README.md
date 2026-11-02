# CorOS Özel Duvar Kağıdı (Custom Wallpaper)

Bu klasöre dilediğiniz herhangi bir görseli (`.png`, `.jpg`, `.jpeg`, `.bmp`) koyabilirsiniz.

### Kullanım:
1. Beğendiğiniz herhangi bir duvar kağıdı görselini bu klasöre (`assets/wallpapers/`) kopyalayın.
2. Terminalden veya PowerShell üzerinden şu komutu çalıştırın:
   ```powershell
   py -3 tools/process_wallpaper.py [görselinizin_adı.png]
   ```
   *(Eğer parametre vermezseniz, klasördeki ilk görseli veya varsayılan siber temayı otomatik olarak 1024x768 24-bit BMP formatına dönüştürür.)*
3. `wallpaper.bmp` oluşturulduğunda işletim sistemini derleyip başlattığınızda (`build.ps1` ve `run-vbox.ps1`), Ayarlar penceresinden **"Özel Wallpaper"** modunu seçerek masaüstünüzde kullanabilirsiniz.
