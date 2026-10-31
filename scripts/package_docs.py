from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

from mkdocs.plugins import event_priority


ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "site"


def package_docs(site_dir: Path) -> None:
    archive_path = site_dir / "offline-docs.zip"
    if not (site_dir / "index.html").is_file():
        raise FileNotFoundError(f"Built documentation not found at {site_dir}")

    with ZipFile(archive_path, "w", compression=ZIP_DEFLATED) as archive:
        for path in site_dir.rglob("*"):
            if path.is_file() and path != archive_path:
                archive.write(path, path.relative_to(site_dir))


@event_priority(-110)
def on_post_build(config) -> None:
    # Run after mkdocs-exporter has written the aggregated PDF.
    package_docs(Path(config["site_dir"]))


def main() -> None:
    package_docs(SITE)


if __name__ == "__main__":
    main()
