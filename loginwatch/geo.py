"""Simulated IP-to-geolocation mapping.

WHY THIS EXISTS
---------------
Real detection stacks resolve a source IP to an approximate location using a
commercial GeoIP database (MaxMind, IPinfo, ...). We have no such database and
no network access, so this module fakes that lookup with a small static table.

Every IP range used here is deliberately NON-ROUTABLE on the public internet:

  * 198.18.0.0/15  - RFC 2544 benchmarking range, never assigned to real hosts
  * 10.0.0.0/8     - RFC 1918 private range, used here for "corporate" sources

So no address in this project can correspond to a real machine or a real
person. That is a hard requirement of the project, not an accident.

The lookup is a simple /24 prefix match, which is the crudest possible model of
how GeoIP actually works (real databases map variable-size CIDR blocks). It is
good enough to drive the impossible-travel detector, and the limitation is
recorded in LIMITATIONS.md.
"""

from __future__ import annotations

import math
from dataclasses import dataclass


@dataclass(frozen=True)
class Site:
    """A physical location that a block of synthetic IPs maps to."""

    name: str
    country: str
    lat: float
    lon: float
    utc_offset_hours: float
    ip_prefix: str  # first three octets, e.g. "198.18.0"
    kind: str = "external"  # "external" | "corp"

    def ip(self, host_octet: int) -> str:
        """Build a concrete synthetic IP inside this site's /24."""
        return f"{self.ip_prefix}.{host_octet}"


# Latitude/longitude are approximate real-world city coordinates (public
# geographic facts) so that distance calculations are realistic. UTC offsets are
# standard-time offsets; daylight saving is deliberately ignored (see
# LIMITATIONS.md).
EXTERNAL_SITES: tuple[Site, ...] = (
    Site("Pune", "IN", 18.52, 73.86, 5.5, "198.18.0"),
    Site("Mumbai", "IN", 19.08, 72.88, 5.5, "198.18.1"),
    Site("Bengaluru", "IN", 12.97, 77.59, 5.5, "198.18.2"),
    Site("Delhi", "IN", 28.61, 77.21, 5.5, "198.18.3"),
    Site("Singapore", "SG", 1.35, 103.82, 8.0, "198.18.4"),
    Site("London", "GB", 51.51, -0.13, 0.0, "198.18.5"),
    Site("Frankfurt", "DE", 50.11, 8.68, 1.0, "198.18.6"),
    Site("Dublin", "IE", 53.35, -6.26, 0.0, "198.18.7"),
    Site("Amsterdam", "NL", 52.37, 4.90, 1.0, "198.18.8"),
    Site("Tallinn", "EE", 59.44, 24.75, 2.0, "198.18.9"),
    Site("New York", "US", 40.71, -74.01, -5.0, "198.18.10"),
    Site("Toronto", "CA", 43.65, -79.38, -5.0, "198.18.11"),
    Site("San Francisco", "US", 37.77, -122.42, -8.0, "198.18.12"),
    Site("Sao Paulo", "BR", -23.55, -46.63, -3.0, "198.18.13"),
    Site("Lagos", "NG", 6.52, 3.38, 1.0, "198.18.14"),
    Site("Moscow", "RU", 55.76, 37.62, 3.0, "198.18.15"),
    Site("Kyiv", "UA", 50.45, 30.52, 2.0, "198.18.16"),
    Site("Hong Kong", "HK", 22.32, 114.17, 8.0, "198.18.17"),
    Site("Sydney", "AU", -33.87, 151.21, 10.0, "198.18.18"),
    Site("Seoul", "KR", 37.57, 126.98, 9.0, "198.18.19"),
    Site("Ho Chi Minh City", "VN", 10.82, 106.63, 7.0, "198.18.20"),
)

# Corporate VPN / office egress. Each city gets an internal 10.10.x/24 that
# geolocates to that same city, because an employee's office is in the place
# they live. Getting this wrong matters more than it looks: if office egress
# lands in a different city to the user's home, every switch between home wifi
# and the VPN reads as intercontinental travel and the impossible-travel
# detector drowns in false positives.
CORP_SITES: tuple[Site, ...] = tuple(
    Site(
        name=f"{site.name} Office",
        country=site.country,
        lat=site.lat,
        lon=site.lon,
        utc_offset_hours=site.utc_offset_hours,
        ip_prefix=f"10.10.{index}",
        kind="corp",
    )
    for index, site in enumerate(EXTERNAL_SITES)
)

SITES: tuple[Site, ...] = EXTERNAL_SITES + CORP_SITES

_BY_PREFIX: dict[str, Site] = {s.ip_prefix: s for s in SITES}
_BY_NAME: dict[str, Site] = {s.name: s for s in SITES}
_CORP_BY_CITY: dict[str, Site] = {s.name: c for s, c in zip(EXTERNAL_SITES, CORP_SITES)}


def lookup(ip: str | None) -> Site | None:
    """Resolve a synthetic IP to a Site, or None if it is outside our table.

    Returning None matters: a real GeoIP database also fails to resolve plenty
    of addresses, and detectors must cope with unknown locations rather than
    assume every event is geolocatable.
    """
    if not ip:
        return None
    octets = ip.split(".")
    if len(octets) != 4:
        return None
    return _BY_PREFIX.get(".".join(octets[:3]))


def site_by_name(name: str) -> Site:
    return _BY_NAME[name]


def external_sites() -> list[Site]:
    return list(EXTERNAL_SITES)


def corp_site_for(site: Site) -> Site:
    """The office egress that serves a given city."""
    return _CORP_BY_CITY[site.name]


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance in kilometres between two points.

    Used by the impossible-travel detector. Great-circle distance is a
    *lower bound* on the real travel distance, which is the conservative
    choice: we may under-estimate speed and miss an attack, but we will not
    invent one out of routing detours.
    """
    radius_km = 6371.0088
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    d_phi = math.radians(lat2 - lat1)
    d_lambda = math.radians(lon2 - lon1)
    a = (
        math.sin(d_phi / 2) ** 2
        + math.cos(phi1) * math.cos(phi2) * math.sin(d_lambda / 2) ** 2
    )
    return 2 * radius_km * math.asin(math.sqrt(a))
