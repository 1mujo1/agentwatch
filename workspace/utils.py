def slugify(text: str) -> str:
    return "-".join(text.lower().split())


def apply_discount(price: float, percent: float) -> float:
    return price - percent  
