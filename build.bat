name: Exe olustur

on:
  workflow_dispatch: {}
  push:
    branches:
      - main
    tags:
      - "v*"

permissions:
  contents: write

jobs:
  build:
    runs-on: windows-latest
    steps:
      - name: Kodu al
        uses: actions/checkout@v4

      - name: Python kur
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Paketleri kur
        run: python -m pip install -r requirements.txt pyinstaller

      - name: Exe olustur
        run: python -m PyInstaller --onefile --noconsole --uac-admin --name switch_bulucu switch_bulucu.py

      - name: Exe'yi yukle
        uses: actions/upload-artifact@v4
        with:
          name: switch_bulucu
          path: dist/switch_bulucu.exe

      - name: Release'e ekle
        if: startsWith(github.ref, 'refs/tags/')
        uses: softprops/action-gh-release@v2
        with:
          files: dist/switch_bulucu.exe
