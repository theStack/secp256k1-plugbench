import seaborn as sns
import matplotlib.pyplot as plt
import pandas as pd
from matplotlib.ticker import LogLocator, FormatStrFormatter

df = pd.read_csv("results.csv")
plt.figure(figsize=(18, 9))

df["project"] = df["version"].str.extract(r"^(os|bc)")
df["date"] = pd.to_datetime(df["date"])
sns.set(style="whitegrid", context="talk")
sns.lineplot(data=df, x="date", y="runtime", hue="project", palette={"os": "darkred", "bc": "green"}, marker="o")
plt.yscale("log")
plt.xlabel("time (release date)")
plt.ylabel("runtime (ms, log scale)")
plt.legend(title="Library")
#plt.tight_layout()
plt.subplots_adjust(top=0.80)
ax = plt.gca()
ax.yaxis.set_major_locator(LogLocator(base=10.0, subs=None))
ax.yaxis.set_major_formatter(FormatStrFormatter('%g'))
plt.title("Benchmark: run-time of verifying 5000 ECDSA signatures per version (smaller is better)\n" +
          "os-... = OpenSSL, bc-... = libsecp256k1 used in specified Bitcoin Core version", pad=40)
# annotate each point with version
for i, row in df.iterrows():
    ax.text(row["date"], row["runtime"], row["version"], fontsize=12, ha='left', va='bottom', rotation=45)
#plt.savefig("openssl_libsecp256k1_bench_results_log.png", format="png", bbox_inches="tight")
plt.savefig("openssl_libsecp256k1_bench_results_log.png", format="png")
plt.show()
