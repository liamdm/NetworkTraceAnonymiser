# Network Trace Anonymiser (Python Reference Implementation)

This repository provides the **reference Python implementation** of the anonymisation framework described in the following publication:

> **A configurable anonymisation approach for network flow data: Balancing utility and privacy**  
> *Liam Daly Manocchio, Siamak Layeghy, David Gwynne, Marius Portmann*  
> *Computers and Electrical Engineering*, Volume 118, Part B, 2024, 109465  
> ISSN 0045-7906  
> DOI: https://doi.org/10.1016/j.compeleceng.2024.109465  
> ScienceDirect: https://www.sciencedirect.com/science/article/pii/S0045790624003926

---

## 📘 Example Notebook

A full demonstration of the anonymisation process is available in the example notebook:

👉 **Open the Example Usage Notebook:** [example_usage.ipynb](./example_usage.ipynb)

---

## ⚙️ Installation

Clone this repository and install dependencies:

```bash
git clone https://github.com/liamdm/NetworkTraceAnonymiser.git
cd NetworkTraceAnonymiser
pip install -r requirements.txt
```

---

## 🧩 Project Structure

```txt
.
├── dataset_anonymiser.py        # Main anonymisation implementation
├── config.yaml                  # Example configuration defining logical IP groups
├── example_usage.ipynb          # Demonstration notebook
├── pseudonym_table.json         # Persistent pseudonym mapping (auto-created)
└── requirements.txt             # Dependencies
```

---

## 🧠 How It Works

1. **Group Definition** – Logical network groups (`servers`, `users`, `external`) are defined in `config.yaml` via IP prefixes and output ranges.  
2. **Prefix Lookup** – A prefix tree assigns each address to a logical group.  
3. **UUID Pseudonymisation** – Each host is assigned a non-reversible 128-bit UUID pseudonym stored for reproducibility.  
4. **Group-based Mapping** – Pseudonyms are mapped into the configured group’s output range to maintain logical structure.  
5. **Reproducibility** – Persistent pseudonym mapping ensures deterministic output across multiple runs.

---

## 🧪 Usage Example

```py
from dataset_anonymiser import DatasetAnonymiser
import pandas as pd

# Load configuration
anon = DatasetAnonymiser("config.yaml")

# Example dataset
df = pd.DataFrame({
    "srcip": ["149.171.126.10", "192.168.1.15", "175.45.176.5"],
    "dstip": ["10.40.170.2", "59.166.0.2", "192.168.3.4"]
})

# Apply anonymisation (with group information)
df_anon = anon.apply_to_dataframe(df, ["srcip", "dstip"], include_logical_groups=True)
anon.save_state()

print(df_anon)
```

---

## 🔁 Adding Groups to an Existing Anonymised Dataset

If you have anonymised IPs and want to re-attach logical group membership:

```py
df_with_groups = anon.add_groups(df_anon)
```

This function maps anonymised IPs back to their logical group based on the output address ranges defined in `config.yaml`.

---

## 🧾 Citation

If you use this code in academic work, please cite:

> **Liam Daly Manocchio, Siamak Layeghy, David Gwynne, Marius Portmann**  
> *A configurable anonymisation approach for network flow data: Balancing utility and privacy.*  
> *Computers and Electrical Engineering*, Volume 118, Part B, 2024, 109465.  
> DOI: https://doi.org/10.1016/j.compeleceng.2024.109465

### BibTeX

```txt
@article{Manocchio2024Anonymisation,
  title   = {A configurable anonymisation approach for network flow data: Balancing utility and privacy},
  author  = {Liam Daly Manocchio and Siamak Layeghy and David Gwynne and Marius Portmann},
  journal = {Computers and Electrical Engineering},
  volume  = {118},
  pages   = {109465},
  year    = {2024},
  issn    = {0045-7906},
  doi     = {10.1016/j.compeleceng.2024.109465},
  url     = {https://www.sciencedirect.com/science/article/pii/S0045790624003926}
}
```
