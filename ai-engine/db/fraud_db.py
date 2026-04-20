import json
from pathlib import Path
from models.fraud import LookupResult, Severity

class JsonFileAdapter:
    def __init__(self, path: Path):
        self.path = path

    def load(self):
        with open(self.path, "r", encoding="utf-8") as f:
            return json.load(f)


class FraudDB:
    def __init__(self, adapter: JsonFileAdapter):
        self.adapter = adapter
        self.data = {}

    async def initialise(self):
        self.data = self.adapter.load()

    async def reload(self):
        self.data = self.adapter.load()

    def stats(self):
        return {
            "phone_numbers": len(self.data.get("phone_numbers", [])),
            "upi_ids": len(self.data.get("upi_ids", [])),
            "urls": len(self.data.get("urls", [])),
        }

    async def lookup_phone(self, number: str):
        for item in self.data.get("phone_numbers", []):
            if item["number"] == number:
                return LookupResult(
                    found=True,
                    entity_type="phone_number",
                    query=number,
                    severity=Severity(item["severity"]),
                    tags=item.get("tags", []),
                    reported_count=item.get("reported_count", 0),
                )
        return LookupResult(found=False, entity_type="phone_number", query=number)

    async def lookup_upi(self, upi_id: str):
        upi_id = upi_id.lower()
        for item in self.data.get("upi_ids", []):
            if item["upi_id"] == upi_id:
                return LookupResult(
                    found=True,
                    entity_type="upi_id",
                    query=upi_id,
                    severity=Severity(item["severity"]),
                    tags=item.get("tags", []),
                    reported_count=item.get("reported_count", 0),
                )
        return LookupResult(found=False, entity_type="upi_id", query=upi_id)

    async def lookup_url(self, url: str):
        for item in self.data.get("urls", []):
            if item["url"] == url:
                return LookupResult(
                    found=True,
                    entity_type="url",
                    query=url,
                    severity=Severity(item["severity"]),
                    tags=item.get("tags", []),
                    reported_count=item.get("reported_count", 0),
                )
        return LookupResult(found=False, entity_type="url", query=url)

    async def add_phone(self, phone):
        self.data["phone_numbers"].append(phone.dict())

    async def add_upi(self, upi):
        self.data["upi_ids"].append(upi.dict())

    async def add_url(self, url):
        self.data["urls"].append(url.dict())