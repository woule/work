# 数据分析脚本：对已核实告警测算前置过滤规则
import pandas as pd

# 只读本题发放的 intrusion_alerts.csv，不补造告警记录
df = pd.read_csv("intrusion_alerts.csv")
print("数据来源: intrusion_alerts.csv")
print(f"原始行数: {len(df)}")
print("补造记录: 无")

labeled = df.dropna(subset=["is_valid"]).copy()
labeled["is_valid"] = labeled["is_valid"].astype(int)

labeled["alert_time"] = pd.to_datetime(labeled["alert_time"], utc=True)
labeled["device_synced_at"] = pd.to_datetime(labeled["device_synced_at"], utc=True)
labeled["sync_delay_sec"] = (
    labeled["alert_time"] - labeled["device_synced_at"]
).dt.total_seconds()

false_alarm_rate = (labeled["is_valid"] == 0).mean()

intercept = (labeled["signal_health"] <= 10) | (labeled["sync_delay_sec"] > 3600)
intercepted = labeled.loc[intercept]

intercept_total = int(len(intercepted))
intercept_false = int((intercepted["is_valid"] == 0).sum())
intercept_true_killed = int((intercepted["is_valid"] == 1).sum())
time_saved = intercept_false * 90
intercept_cost = intercept_total * 15
net_saved = time_saved - intercept_cost

print(f"已核实告警数: {len(labeled)}")
print(f"误报率: {false_alarm_rate:.4f}")
print(f"拦截总数: {intercept_total}")
print(f"拦截误报数: {intercept_false}")
print(f"误杀真实报警数: {intercept_true_killed}")
print(f"节省时间_分钟: {time_saved}")
print(f"拦截成本_分钟: {intercept_cost}")
print(f"净节省时间_分钟: {net_saved}")
