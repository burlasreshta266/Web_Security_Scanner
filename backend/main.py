from fastapi import FastAPI, Query
import sqlite3
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from scanner import Scanner

app = FastAPI()

orgins = [
    "http://localhost:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=orgins,
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True,
)


class ScanRequest(BaseModel):
    url: str


@app.get("/filter")
def filter_data(category: str, price: str):
    try:
        conn = sqlite3.connect("test.db")
        cursor = conn.cursor()
        query = f"SELECT * FROM products WHERE category='{category}' AND price={price}"
        cursor.execute(query)
        return {"data": cursor.fetchall()}
    except Exception as e:
        return {"error": str(e)}    

@app.post("/scan")
def scan(request: ScanRequest):
    scanner = Scanner(request.url)
    scanner.scan()
    return {"vulnerabilities": scanner.vulnerabilities}