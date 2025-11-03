import ipaddress
import uuid
import warnings
from pathlib import Path
import radix
import yaml
import os
import pandas as pd
from typing import Dict, Tuple, List, Optional


class DatasetAnonymiser:
    """
    Reference Python implementation of the proposed anonymisation framework.

    Implements:
        A' = G[i]_0 + (p mod (G[i]_1 - G[i]_0))
    where:
        h(A) = UUID-based pseudonym function (non-reversible)
        g(A) = IP prefix-tree group mapping
    """

    def __init__(self, config_path: str, state_path: str = "pseudonym_table.json"):
        """
        :param config_path: YAML configuration defining groups, prefixes, and output ranges.
        :param state_path: Optional path for saving the pseudonym table across runs.
        """
        with open(config_path, "r") as f:
            self.config = yaml.safe_load(f)

        # Build prefix tree for group resolution (original IPs)
        self.trie = IPRadixLookup()
        for group, spec in self.config["groups"].items():
            for prefix in spec["prefixes"]:
                self.trie.insert(prefix, group)

        # Define output address ranges (for anonymised IPs)
        self.group_ranges: Dict[str, Tuple[int, int]] = {
            group: (
                int(ipaddress.IPv4Address(spec["output_range"]["start"])),
                int(ipaddress.IPv4Address(spec["output_range"]["end"]))
            )
            for group, spec in self.config["groups"].items()
        }
        # Flatten into a list for quick scan when deducing group from anonymised IPs
        self.output_ranges_list: List[Tuple[int, int, str]] = [
            (start, end, group) for group, (start, end) in self.group_ranges.items()
        ]

        self.state_path = state_path
        self.pseudonyms: Dict[str, int] = {}

        if os.path.exists(state_path):
            txt = Path(state_path).read_text()
            if txt.startswith("{") or txt.strip().startswith("["):
                try:
                    df = pd.read_json(state_path)
                    self.pseudonyms = {
                        host: int(pseudo) for host, pseudo in zip(df["host"], df["pseudonym"])
                    }
                except Exception as ex:
                    warnings.warn(f"State path provided was invalid: {ex}")

    # ------------------ Core components ------------------

    def _h(self, addr: str) -> int:
        """Return 128-bit UUID pseudonym for this host."""
        if addr not in self.pseudonyms:
            u = uuid.uuid4()
            self.pseudonyms[addr] = u.int
        return self.pseudonyms[addr]

    def _g(self, addr: str) -> Optional[str]:
        """Resolve logical group from original IP using prefix-tree."""
        return self.trie.get(addr)

    def _g_from_output(self, addr: str) -> Optional[str]:
        """
        Resolve logical group from an anonymised IP by finding which output_range contains it.
        """
        try:
            val = int(ipaddress.IPv4Address(addr))
        except Exception:
            return None
        for start, end, group in self.output_ranges_list:
            # Treat range as inclusive on both ends for lookup
            if start <= val <= end:
                return group
        return None

    def _combine(self, group: str, pseudonym: int) -> str:
        """Compute anonymised address per Eq. (4)."""
        start, end = self.group_ranges[group]
        diff = end - start
        anon_int = start + (pseudonym % diff)
        return str(ipaddress.IPv4Address(anon_int))

    # ------------------ Public interface ------------------

    def anonymise_ip(self, addr: str) -> str:
        """Anonymise one IPv4 address."""
        group = self._g(addr)
        if group is None:
            return addr
        p = self._h(addr)
        return self._combine(group, p)

    def apply_to_dataframe(
            self,
            df: pd.DataFrame,
            columns: List[str],
            include_logical_groups: bool = False
    ) -> pd.DataFrame:
        """
        Anonymise selected IP address columns, optionally including group information.

        :param df: Input DataFrame.
        :param columns: Columns containing original IP addresses.
        :param include_logical_groups: If True, add columns showing group membership (from original IPs).
        """
        df = df.copy()
        for col in columns:
            if include_logical_groups:
                df[f"{col}_group"] = df[col].apply(self._g)
            df[f"{col}_anon"] = df[col].apply(self.anonymise_ip)
        return df

    def add_groups(
        self,
        df: pd.DataFrame,
        columns: Optional[List[str]] = None,
        unknown_label: Optional[str] = None
    ) -> pd.DataFrame:
        """
        Add logical group columns to an existing (possibly anonymised) trace DataFrame.

        This version enforces explicit column labeling — it requires that certain
        columns (defined in `required_columns`) are present in the input DataFrame.

        :param df: DataFrame containing explicitly labeled IP or anonymised IP columns.
        :param columns: List of column names that must exist in the DataFrame.
        :param unknown_label: Optional label to use when a value cannot be mapped.
        :return: A new DataFrame with added *_group columns.
        """
        if columns is None:
            raise ValueError("You must provide `columns` listing expected IP columns.")

        missing = [c for c in columns if c not in df.columns]
        if missing:
            raise ValueError(f"Missing required columns: {missing}")

        df = df.copy()

        def resolve_group(value: str) -> Optional[str]:
            g = self._g(value)
            if g is not None:
                return g
            g2 = self._g_from_output(value)
            if g2 is not None:
                return g2
            return unknown_label

        for col in columns:
            df[f"{col}_group"] = df[col].apply(resolve_group)

        return df

    def save_state(self) -> None:
        """Persist pseudonym mapping for reproducibility."""
        df = pd.DataFrame(
            [(host, str(pseudo)) for host, pseudo in self.pseudonyms.items()],
            columns=["host", "pseudonym"]
        )
        df.to_json(self.state_path, orient="records")


class IPRadixLookup:

    def __init__(self):
        self._tree = radix.Radix()

    def insert(self, prefix: str, value):
        """Insert a CIDR prefix mapping to a value."""
        node = self._tree.add(prefix)
        node.data["value"] = value

    def get(self, ip_addr: str):
        """Return the value associated with the best-matching prefix."""
        node = self._tree.search_best(ip_addr)
        return node.data["value"] if node else None
