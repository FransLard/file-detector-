# API

## GET /
UI drag and drop.

## POST /api/scan
Form-data `file`. Query `reputation=1/0`. Response JSON berisi score, verdict, family, reasons.

## GET /api/eicar
Unduh string uji EICAR.

## GET /api/health
Status engine berisi pefile, yara, max_bytes, version.
