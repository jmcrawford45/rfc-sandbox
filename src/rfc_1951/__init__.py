from collections import namedtuple
import sqlite3

import cv2
import numpy as np
import pytesseract
from ratelimit import limits, sleep_and_retry
import requests

Card = namedtuple("Card", ["id", "name", "image"])

# def text_boxes_from_image(path: str):
#   custom_config = r"--psm 11 --oem 3"
#   img = cv2.imread(path)
#   img = cv2.convertScaleAbs(img, alpha=3, beta=0)
#   img = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
#   # ret, img = cv2.threshold(gray, 50, 255, cv2.THRESH_BINARY)
#   h, w = img.shape
#   boxes = pytesseract.image_to_boxes(img, config=custom_config)
#   for b in boxes.splitlines():
#       b = b.split(' ')
#       img = cv2.rectangle(img, (int(b[1]), h - int(b[2])), (int(b[3]), h - int(b[4])), (0, 255, 0), 2)

#   cv2.imshow('img', img)
#   cv2.waitKey(0)


def text_from_card(id: int) -> str:
    nparr = np.fromstring(_get_cardinfo(id).image, np.uint8)
    img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
    img = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    custom_config = r"--oem 3 --psm 6"
    return pytesseract.image_to_string(img, config=custom_config).upper()


@sleep_and_retry
@limits(calls=10, period=1)
def _get_rate_limited(*args, **kwargs):
    return requests.get(*args, **kwargs)


def _get_remote_cardinfo(**kwargs) -> list[Card]:
    r = _get_rate_limited(
        "https://db.ygoprodeck.com/api/v7/cardinfo.php", params=kwargs
    )
    r.raise_for_status()
    body = r.json()
    cards = []
    for datum in body["data"]:
        for image in datum["card_images"]:
            image_binary = _get_rate_limited(image["image_url"])
            image_binary.raise_for_status()
            cards.append(
                Card(datum["name"], image["id"], image_binary.content)
            )
    return cards


def _store_cardinfo(name: str):
    conn = sqlite3.connect("cardboard_db.sqlite")
    cur = conn.cursor()
    if cur.execute(
        "SELECT count(*) from card WHERE name = ?", (name,)
    ).fetchone()[0]:
        return
    cur.execute(
        "CREATE TABLE IF NOT EXISTS card (id INT PRIMARY KEY, name TEXT NOT NULL, image BLOB NOT NULL)"
    )
    for card in _get_remote_cardinfo(name=name):
        cur.execute(
            "INSERT INTO card VALUES (?, ?, ?)",
            (card.id, card.name, card.image),
        )
    conn.commit()
    conn.close()


def _get_cardinfo(id: int):
    conn = sqlite3.connect("cardboard_db.sqlite")
    cur = conn.cursor()
    card = cur.execute("SELECT * from card WHERE ID = ?", (id,)).fetchone()
    conn.close()
    return Card(*card)


def _get_cardinfo_by_name(name: str):
    conn = sqlite3.connect("cardboard_db.sqlite")
    cur = conn.cursor()
    cards = cur.execute(
        "SELECT * from card WHERE NAME = ?", (name,)
    ).fetchall()
    conn.close()
    return [Card(*card) for card in cards]


all = "card_from_image"
