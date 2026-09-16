from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw


def build_icon(output: Path) -> None:
    size = 512
    image = Image.new("RGBA", (size, size), (7, 17, 31, 255))
    draw = ImageDraw.Draw(image)

    draw.rounded_rectangle((20, 20, 492, 492), radius=110, fill=(10, 22, 40, 255), outline=(30, 58, 138, 255), width=10)
    draw.ellipse((90, 90, 422, 422), outline=(14, 165, 233, 45), width=16)

    # Radar arcs
    draw.arc((68, 143, 306, 381), start=0, end=90, fill=(56, 189, 248, 255), width=24)
    draw.arc((43, 115, 365, 437), start=0, end=90, fill=(56, 189, 248, 210), width=17)

    # Dish
    draw.polygon([(128, 317), (220, 363), (158, 426)], fill=(226, 232, 240, 255))
    draw.line((222, 349, 276, 273), fill=(96, 165, 250, 255), width=16)

    # Signal source
    draw.ellipse((256, 154, 316, 214), fill=(56, 189, 248, 255))
    draw.ellipse((274, 172, 298, 196), fill=(224, 242, 254, 255))

    # Receiver tile
    draw.rounded_rectangle((327, 300, 409, 362), radius=12, fill=(15, 23, 42, 255), outline=(56, 189, 248, 255), width=8)
    draw.ellipse((344, 324, 358, 338), fill=(34, 197, 94, 255))
    draw.line((370, 322, 391, 322), fill=(147, 197, 253, 255), width=7)
    draw.line((370, 340, 391, 340), fill=(147, 197, 253, 255), width=7)

    output.parent.mkdir(parents=True, exist_ok=True)
    image.save(output, format="ICO", sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])


if __name__ == "__main__":
    build_icon(Path("assets/dreambox-scanner.ico"))
    print("Built assets/dreambox-scanner.ico")
