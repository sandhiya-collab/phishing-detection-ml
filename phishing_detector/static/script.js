async function analyze(event) {
    event.preventDefault();

    const message = document.querySelector("textarea").value;
    const inputType = document.querySelector("select[name='input_type']").value;

    const loader = document.getElementById("loader");
    const resultBox = document.getElementById("resultBox");

    loader.classList.remove("hidden");
    resultBox.style.display = "none";

    try {
        const response = await fetch("/predict", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({ input: message, type: inputType })
        });

        const data = await response.json();

        // Result text with color
        const resultText = document.getElementById("resultText");
        resultText.textContent = data.result;
        resultText.className = data.result.toLowerCase();

        document.getElementById("confidenceText").textContent =
            "Confidence: " + data.confidence + "%";

        // Populate explanation table
        const tbody = document.querySelector("#explanationTable tbody");
        tbody.innerHTML = "";

        const labels = [
            "Google Safe Browsing",
            "VirusTotal",
            "Domain Age",
            "AI Heuristic"
        ];

        const parts = data.explanation.split(" | ");

        for (let i = 0; i < labels.length; i++) {
            const tr = document.createElement("tr");

            let cellClass = "";
            const text = (parts[i] || "").toLowerCase();

            if (labels[i] === "AI Heuristic") {
                if (text.includes("potential typosquatting") || text.includes("phishing")) {
                    cellClass = "phishing";
                } else if (text.includes("suspicious")) {
                    cellClass = "suspicious";
                } else {
                    cellClass = "safe";
                }
            }

            tr.innerHTML = `
                <td>${labels[i]}</td>
                <td class="${cellClass}">${parts[i] || "-"}</td>
            `;
            tbody.appendChild(tr);
        }

        resultBox.style.display = "block";

    } catch (e) {
        alert("Error analyzing content");
    } finally {
        loader.classList.add("hidden");
    }
}
