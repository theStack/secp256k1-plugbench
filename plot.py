import seaborn as sns
import matplotlib.pyplot as plt
import pandas as pd

df = pd.read_csv("results.csv")
plt.figure(figsize=(18, 6))

def get_prefix(version):
    return version[:2]
prefixes = df['version'].apply(get_prefix)
palette = {'os': 'lightblue', 'bc': 'orange'}

norm = plt.Normalize(min(df['runtime']), max(df['runtime']))
#cmap = plt.get_cmap('coolwarm')
#cmap = plt.get_cmap('inferno')
cmap = plt.get_cmap('RdYlGn_r')

#sns.barplot(x='version',y='runtime',data=df,palette='RdYlGn')
sns.barplot(x='version',y='runtime',data=df,palette=[cmap(norm(val)) for val in df['runtime']])
plt.title("Benchmark: run-time of verifying 5000 ECDSA signatures per version (smaller is better)\n" +
          "os-... = OpenSSL, bc-... = libsecp256k1 used in specified Bitcoin Core version")
plt.xlabel("version")
plt.ylabel("runtime (ms)")
plt.savefig("openssl_libsecp256k1_bench_results.png", format="png")
plt.show()
