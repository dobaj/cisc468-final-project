def clean_text(value: str) -> str:
    if value is None:
        return ""
    return value.replace("\ufeff", "").strip()
