# media

Inventory of shared storage: hashes, EXIF dates and devices, GPS positions,
hash-set matches, and maps.

## Prerequisites

- A case acquired with `device acquire --storage`, or imported with
  `import --storage`. Without it, `media` says there is no shared storage.
- Optional: alert hash sets (`--hashes`) and known-file hash sets (`--known`).
  See [Indicators and hash sets](Indicators-and-Hash-Sets).

No phone, no network.

## Usage

```sh
apex media ./case-42                                        # → ./case-42_media/
apex media ./case-42 --hashes vics.json --known NSRLFile.txt -o ./case-42-media
```

| Option | Effect |
|---|---|
| `--hashes <FILE>` | alert hash set (repeatable): VICS JSON (with category) or one hash per line; a match is flagged and raises `HASH_SET_MATCH` |
| `--known <FILE>` | known-file hash set (repeatable): NSRL (`NSRLFile.txt` or RDSv3 SQLite) or one hash per line; matches are set aside |
| `-o, --output <DIR>` | output directory (default `<case>_media`) |

## Output

| File | Content |
|---|---|
| `media.csv` | `path, size, sha256, sha1, md5, taken, make, model, latitude, longitude, known, alert` |
| `locations.kml` | located photos and videos (Google Earth, QGIS) |
| `locations.geojson` | the same, GeoJSON |

Photo positions come from EXIF, video positions from the MP4 / MOV `©xyz`
atom. Dated media go into the [timeline](Timeline) with their position.
