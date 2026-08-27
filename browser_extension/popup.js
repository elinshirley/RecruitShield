const analyzeBtn = document.getElementById("analyzeBtn");

const loading = document.getElementById("loading");
const result = document.getElementById("result");
const errorBox = document.getElementById("error");
const errorMessage = document.getElementById("errorMessage");

const trustScore = document.getElementById("trustScore");
const scoreCircle = document.getElementById("scoreCircle");

const verdictEmoji = document.getElementById("verdictEmoji");
const verdictText = document.getElementById("verdictText");
const verdictBox = document.getElementById("verdictBox");

const redFlags = document.getElementById("redFlags");
const recommendations = document.getElementById("recommendations");


// Analyze button click
analyzeBtn.addEventListener("click", async () => {

    // Reset UI
    result.classList.add("hidden");
    errorBox.classList.add("hidden");

    loading.classList.remove("hidden");

    analyzeBtn.disabled = true;
    analyzeBtn.innerText = "Analyzing...";

    try {

        // Get current active browser tab
        const [tab] = await chrome.tabs.query({
            active: true,
            currentWindow: true
        });


        // Ask content.js for job posting text
        const response = await chrome.tabs.sendMessage(
            tab.id,
            {
                action: "GET_JOB_TEXT"
            }
        );


        if (!response || !response.success) {
            throw new Error(
                "Could not extract job posting text."
            );
        }


        // Check if enough content exists
        if (!response.content || response.content.length < 30) {
            throw new Error(
                "No job posting text found on this page."
            );
        }


        // Send extracted job text to Flask backend
        const apiResponse = await fetch(
            "http://127.0.0.1:5000/api/extension/analyze",
            {
                method: "POST",

                headers: {
                    "Content-Type": "application/json"
                },

                body: JSON.stringify({
                    content: response.content,
                    platform: response.platform,
                    url: response.pageUrl
                })
            }
        );


        if (!apiResponse.ok) {
            throw new Error(
                "Backend API is not responding. Make sure main.py is running."
            );
        }


        const data = await apiResponse.json();


        if (!data.success) {
            throw new Error(
                "Analysis failed."
            );
        }


        // Display analysis result
        displayResult(data);

    }
    catch (error) {

        console.error(error);

        errorMessage.innerText =
            "❌ " + error.message;

        errorBox.classList.remove("hidden");
    }
    finally {

        loading.classList.add("hidden");

        analyzeBtn.disabled = false;

        analyzeBtn.innerText =
            "🔍 Analyze This Job";
    }

});


// Display API result
function displayResult(data) {

    result.classList.remove("hidden");


    // Trust Score
    trustScore.innerText = data.trust_score;


    // Remove previous risk classes
    scoreCircle.classList.remove(
        "safe",
        "caution",
        "danger"
    );

    verdictBox.classList.remove(
        "safe",
        "caution",
        "danger"
    );


    // Set color according to trust score
    if (data.trust_score >= 80) {

        scoreCircle.classList.add("safe");
        verdictBox.classList.add("safe");

    }
    else if (data.trust_score >= 50) {

        scoreCircle.classList.add("caution");
        verdictBox.classList.add("caution");

    }
    else {

        scoreCircle.classList.add("danger");
        verdictBox.classList.add("danger");
    }


    // Verdict
    verdictEmoji.innerText =
        data.verdict.emoji;

    verdictText.innerText =
        data.verdict.label +
        " (" +
        data.verdict.level +
        ")";


    // Red Flags
    redFlags.innerHTML = "";

    if (data.red_flags.length === 0) {

        redFlags.innerHTML =
            "<p>✅ No major red flags detected.</p>";

    }
    else {

        const flagList =
            document.createElement("ul");

        data.red_flags.forEach(flag => {

            const item =
                document.createElement("li");

            item.innerHTML =
                `<strong>[${flag.risk}]</strong><br>
                 ${flag.reason}`;

            flagList.appendChild(item);

        });

        redFlags.appendChild(flagList);
    }


    // Recommendations
    recommendations.innerHTML = "";

    const recommendationList =
        document.createElement("ul");

    data.recommendations.forEach(item => {

        const listItem =
            document.createElement("li");

        listItem.innerText = item;

        recommendationList.appendChild(listItem);

    });

    recommendations.appendChild(
        recommendationList
    );
}