#!/usr/bin/env python3
"""Script pour générer le payload JSON (body) à fournir à l'API Mistral OCR à partir d'un fichier PDF (ou image)."""

import argparse
import base64
import json
import mimetypes
import sys
from pathlib import Path


def generate_payload(file_path: str, model: str = "mistral-ocr-2512") -> dict:
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(
            f"Le fichier '{file_path}' n'existe pas ou n'est pas un fichier valide."
        )

    mime_type, _ = mimetypes.guess_type(path)
    if not mime_type:
        mime_type = (
            "application/pdf"
            if path.suffix.lower() == ".pdf"
            else "application/octet-stream"
        )

    raw_bytes = path.read_bytes()
    b64_content = base64.b64encode(raw_bytes).decode("ascii")

    data_url = f"data:{mime_type};base64,{b64_content}"

    if mime_type.startswith("image/"):
        document_content = {
            "type": "image_url",
            "image_url": data_url,
        }
    else:
        document_content = {
            "type": "document_url",
            "document_url": data_url,
        }

    return {
        "model": model,
        "document": document_content,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Génère le body du payload JSON pour l'API Mistral OCR à partir d'un fichier PDF ou image."
    )
    parser.add_argument(
        "file_path", type=str, help="Chemin vers le fichier PDF (ou image) en entrée."
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default=None,
        help="Chemin du fichier JSON de sortie où enregistrer le payload (facultatif). Si non renseigné, affiche le JSON sur stdout.",
    )
    parser.add_argument(
        "--model",
        type=str,
        default="mistral-ocr-2512",
        help="Modèle Mistral OCR à utiliser (par défaut: mistral-ocr-2512).",
    )

    args = parser.parse_args()

    try:
        payload = generate_payload(args.file_path, model=args.model)
        json_output = json.dumps(payload, indent=2)

        if args.output:
            out_path = Path(args.output)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(json_output, encoding="utf-8")
            print(
                f"Payload enregistré avec succès dans '{args.output}'.", file=sys.stderr
            )
        else:
            print(json_output)
    except Exception as e:
        print(f"Erreur : {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
