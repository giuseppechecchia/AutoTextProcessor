#!/bin/bash

# Funzione per verificare se un pacchetto è installato
is_installed() {
    command -v "$1" > /dev/null 2>&1
}

# Installazione di unrtf per la gestione dei file RTF
if ! is_installed "unrtf"; then
    echo "Installazione di unrtf..."
    sudo apt-get update
    sudo apt-get install -y unrtf
fi

# Installazione di libcurl4-openssl-dev
if ! is_installed "libcurl4-openssl-dev"; then
    echo "Installazione di libcurl4-openssl-dev..."
    sudo apt-get update
    sudo apt-get install -y libcurl4-openssl-dev
fi

# Installazione di libcjson-dev
if ! is_installed "libcjson-dev"; then
    echo "Installazione di libcjson-dev..."
    sudo apt-get update
    sudo apt-get install -y libcjson-dev
fi

# Installazione di antiword per la gestione dei file DOC
if ! is_installed "antiword"; then
    echo "Installazione di antiword..."
    sudo apt-get update
    sudo apt-get install -y antiword
fi

# Installazione di LibreOffice per la gestione dei file DOCX
if ! is_installed "libreoffice"; then
    echo "Installazione di LibreOffice..."
    sudo apt-get update
    sudo apt-get install -y libreoffice
fi

# Installazione di sqlite3 per la gestione del database
if ! is_installed "sqlite3"; then
    echo "Installazione di sqlite3..."
    sudo apt-get update
    sudo apt-get install -y sqlite3 libsqlite3-dev
fi

# Installazione di tesseract per l'OCR sui file PDF
if ! is_installed "tesseract"; then
    echo "Installazione di Tesseract OCR..."
    sudo apt-get update
    sudo apt-get install -y tesseract-ocr
fi

# Installazione di pdftoppm per la conversione dei PDF in immagini
if ! is_installed "pdftoppm"; then
    echo "Installazione di Poppler Utils per pdftoppm..."
    sudo apt-get update
    sudo apt-get install -y poppler-utils
fi

# Installazione di ImageMagick per la gestione delle immagini
if ! is_installed "convert"; then
    echo "Installazione di ImageMagick..."
    sudo apt-get update
    sudo apt-get install -y imagemagick
fi

echo "Tutte le dipendenze sono state installate correttamente."

START_DIR="$(pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Compila il programma C utilizzando il percorso assoluto
gcc -o document_parser "$SCRIPT_DIR/document_parser.c" -lsqlite3 -lpthread -lcurl -lcjson

if [ $? -eq 0 ]; then
    echo "Compilazione completata con successo."
else
    echo "Errore durante la compilazione."
    cd "$START_DIR"
    exit 1
fi
