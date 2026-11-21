from utils import apply_discount, slugify


def test_slugify():
    assert slugify("Hello World") == "hello-world"


def test_apply_discount():
    assert apply_discount(200, 25) == 150
