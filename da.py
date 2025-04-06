import pandas as pd
import numpy as np
import seaborn as sns
import matplotlib.pyplot as plt
import scipy.stats as stats
from scipy.stats import spearmanr
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score, roc_curve
import warnings
warnings.filterwarnings("ignore")

# ======================= Load Dataset ======================= #
df = pd.read_csv("ransomware_dataset.csv")

# Ensure required columns exist
if "DebugSize" not in df.columns or "ResourceSize" not in df.columns or "Benign" not in df.columns:
    raise ValueError("Dataset must contain 'DebugSize', 'ResourceSize', and 'Benign' columns.")

# ======================= Descriptive Statistics ======================= #
summary_table = df.groupby("Benign")["DebugSize"].describe()[["mean", "std", "min", "max"]]
print("\nSummary Statistics for Debug Size across Benign Status:")
print(summary_table)

# ======================= Spearman Correlation Analysis ======================= #
rho, p_value = spearmanr(df["DebugSize"], df["ResourceSize"])

# Interpret correlation strength
def interpret_spearman(rho):
    if abs(rho) >= 0.7:
        return "Strong"
    elif abs(rho) >= 0.4:
        return "Moderate"
    elif abs(rho) > 0:
        return "Weak"
    else:
        return "No"

strength = interpret_spearman(rho)
correlation_type = "Positive" if rho > 0 else "Negative"

print(f"\nSpearman’s Rank Correlation (ρ): {rho:.3f}")
print(f"P-value: {p_value:.5f}")
print(f"Strength of Correlation: {strength} {correlation_type}")

if p_value < 0.05:
    print("The correlation is statistically significant.")
else:
    print("No significant correlation found.")

# ======================= Jitter Plot ======================= #
plt.figure(figsize=(6, 4))
sns.stripplot(x=df["Benign"], y=df["DebugSize"], jitter=True, alpha=0.5)
plt.xticks([0, 1], ["Malware", "Benign"])
plt.xlabel("Benign Status")
plt.ylabel("Debug Size")
plt.title("Debug Size Distribution in Malware and Benign Files")
plt.show()

# ======================= Box Plot with Mann-Whitney U Test ======================= #
plt.figure(figsize=(6, 4))
sns.boxplot(x=df["Benign"], y=df["DebugSize"], palette="Set2")
plt.xticks([0, 1], ["Malware", "Benign"])
plt.xlabel("Benign Status")
plt.ylabel("Debug Size")
plt.title("Box Plot: Debug Size Across Malware and Benign Files")
plt.show()

# Mann-Whitney U Test
malware_debug = df[df["Benign"] == 0]["DebugSize"]
benign_debug = df[df["Benign"] == 1]["DebugSize"]
u_stat, p_mannwhitney = stats.mannwhitneyu(malware_debug, benign_debug)

print(f"\nMann-Whitney U Test p-value: {p_mannwhitney:.5f}")
if p_mannwhitney < 0.05:
    print("Debug Size significantly differs between Malware and Benign files.")
else:
    print("No significant difference found in Debug Size.")

# ======================= Risk Probability Curve (Logistic Regression) ======================= #
X = df[["DebugSize"]].values
y = df["Benign"].values

# Fit Logistic Regression
model = LogisticRegression()
model.fit(X, y)

# Compute predicted probabilities
y_pred_prob = model.predict_proba(X)[:, 1]

# Compute AUC
auc_score = roc_auc_score(y, y_pred_prob)

# Plot ROC Curve
fpr, tpr, _ = roc_curve(y, y_pred_prob)

plt.figure(figsize=(6, 4))
plt.plot(fpr, tpr, color="blue", label=f"AUC = {auc_score:.2f}")
plt.plot([0, 1], [0, 1], linestyle="--", color="gray")  # Diagonal line
plt.xlabel("False Positive Rate")
plt.ylabel("True Positive Rate")
plt.title("ROC Curve: Debug Size as Predictor of Benign Status")
plt.legend()
plt.show()

# ======================= Heatmap Correlation ======================= #
correlation_matrix = df[["DebugSize", "ResourceSize", "Benign"]].corr(method="spearman")

plt.figure(figsize=(6, 4))
sns.heatmap(correlation_matrix, annot=True, cmap="coolwarm", fmt=".2f", linewidths=0.5)
plt.title("Spearman Correlation Heatmap: Debug Size vs Resource Size")
plt.show()

# ======================= Logistic Regression Analysis ======================= #
odds_ratio = np.exp(model.coef_[0][0])
print(f"\nLogistic Regression: Odds Ratio for Debug Size = {odds_ratio:.3f}")

