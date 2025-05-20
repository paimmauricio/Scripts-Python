import pandas as pd
import re
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime, timedelta

# === CONFIGURAÇÃO DO LOG ===
LOG_FILE = "C:/Users/mauricio/Downloads/Firewall/2025/Maio/fortianalyzer-event-vpn-2025_05_20.log"

# === EXPRESSÃO REGULAR ===
pattern = re.compile(
    r'date=(?P<date>\d{4}-\d{2}-\d{2}) time=(?P<time>\d{2}:\d{2}:\d{2})|'
    r'user="(?P<user>[^"]+)"|action="(?P<action>[^"]+)"|duration=(?P<duration>\d+)|'
    r'reason="(?P<reason>[^"]+)"|remip=(?P<remip>[0-9.]+)|srccountry="(?P<srccountry>[^"]+)"|group="(?P<group>[^"]+)"'
)

records = []
with open(LOG_FILE, "r") as f:
    for line in f:
        entry = {
            "date": None, "time": None, "user": None, "action": None,
            "duration": 0, "reason": None, "remip": None, "srccountry": None, "group": None
        }
        for match in pattern.findall(line):
            if match[0]: entry["date"] = match[0]
            if match[1]: entry["time"] = match[1]
            if match[2]: entry["user"] = match[2]
            if match[3]: entry["action"] = match[3]
            if match[4]: entry["duration"] = int(match[4])
            if match[5]: entry["reason"] = match[5]
            if match[6]: entry["remip"] = match[6]
            if match[7]: entry["srccountry"] = match[7]
            if match[8]: entry["group"] = match[8]
        if entry["user"] and entry["action"]:
            records.append(entry)

df = pd.DataFrame(records)
df["datetime"] = pd.to_datetime(df["date"] + " " + df["time"], errors="coerce")
df["hour"] = df["datetime"].dt.hour
df["date"] = df["datetime"].dt.date

# === ESTATÍSTICAS POR USUÁRIO ===
user_stats = df.groupby("user").agg(
    total_events=("action", "count"),
    success_connections=("action", lambda x: (x == "tunnel-up").sum()),
    disconnections=("action", lambda x: (x == "tunnel-down").sum()),
    failed_logins=("action", lambda x: (x == "ssl-login-fail").sum()),
    total_duration_sec=("duration", "sum")
).reset_index()
user_stats["total_duration"] = user_stats["total_duration_sec"].apply(lambda x: str(timedelta(seconds=x)))

# === IPs relacionados a usuários ===
ip_user_counts = df.groupby(["user", "remip"]).size().reset_index(name="total_conexoes")
top_user_ips = ip_user_counts.sort_values("total_conexoes", ascending=False).head(10)

# === Falhas de login ===
falhas = df[df["action"] == "ssl-login-fail"].groupby(["user", "remip", "reason"]).size().reset_index(name="count")

# === Análises por dia e hora ===
por_dia = df.groupby("date").size().reset_index(name="total")
por_hora = df.groupby("hour").size().reset_index(name="total")

# === SAÍDA NA TELA ===
print("\n=== Resumo por Usuário ===")
for _, row in user_stats.iterrows():
    print(f"- Usuário: {row['user']}")
    print(f"  Total eventos: {row['total_events']}")
    print(f"  Conexões: {row['success_connections']}, Desconexões: {row['disconnections']}, Falhas: {row['failed_logins']}")
    print(f"  Duração total: {row['total_duration']}")
    print("")

print("\n=== Falhas de Login ===")
for _, row in falhas.iterrows():
    print(f"- Usuário: {row['user']} | IP: {row['remip']} | Motivo: {row['reason']} | Qtde: {row['count']}")

print("\n=== Top IPs por Usuário ===")
for _, row in top_user_ips.iterrows():
    print(f"- Usuário: {row['user']} | IP: {row['remip']} | Conexões: {row['total_conexoes']}")

print("\n=== Eventos por Dia ===")
for _, row in por_dia.iterrows():
    print(f"- {row['date']}: {row['total']} eventos")

print("\n=== Eventos por Hora ===")
for _, row in por_hora.iterrows():
    print(f"- {row['hour']:02d}h: {row['total']} eventos")

# === GRÁFICOS ===
sns.set(style="whitegrid")

plt.figure(figsize=(6, 4))
sns.countplot(data=df, x="action", order=df["action"].value_counts().index)
plt.title("Distribuição de Ações VPN")
plt.xticks(rotation=30)
plt.tight_layout()
plt.savefig("grafico_acoes.png")
print("\n📊 Gráfico salvo: grafico_acoes.png")

plt.figure(figsize=(8, 4))
sns.barplot(data=user_stats, x="user", y="total_duration_sec")
plt.title("Duração Total por Usuário (s)")
plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig("grafico_duracao.png")
print("📊 Gráfico salvo: grafico_duracao.png")

plt.figure(figsize=(8, 4))
sns.barplot(data=top_user_ips, x="remip", y="total_conexoes", hue="user", dodge=False)
plt.title("Top IPs de Origem com Usuários")
plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig("grafico_ips_usuarios.png")
print("📊 Gráfico salvo: grafico_ips_usuarios.png")

plt.figure(figsize=(6, 4))
sns.barplot(data=por_dia, x="date", y="total")
plt.title("Total de Eventos por Dia")
plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig("grafico_por_dia.png")
print("📊 Gráfico salvo: grafico_por_dia.png")

plt.figure(figsize=(6, 4))
sns.barplot(data=por_hora, x="hour", y="total")
plt.title("Total de Eventos por Hora do Dia")
plt.xticks(rotation=0)
plt.tight_layout()
plt.savefig("grafico_por_hora.png")
print("📊 Gráfico salvo: grafico_por_hora.png")
