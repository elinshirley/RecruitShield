// Recruitment Scam Detector - Content Script

console.log("Recruitment Scam Detector content script loaded");

// Get visible text from the current job page
function getJobPostingText() {
    const selectors = [
        // LinkedIn
        ".jobs-description",
        ".jobs-description-content",

        // Naukri
        ".job-desc",
        ".styles_job-desc__",

        // Indeed
        "#jobDescriptionText",
        ".jobsearch-jobDescriptionText",

        // Generic fallback
        "main",
        "body"
    ];

    for (const selector of selectors) {
        const element = document.querySelector(selector);

        if (element && element.innerText.trim().length > 100) {
            return element.innerText.trim();
        }
    }

    return document.body.innerText.trim();
}


// Listen for messages from popup.js
chrome.runtime.onMessage.addListener(
    (request, sender, sendResponse) => {

        if (request.action === "GET_JOB_TEXT") {

            const jobText = getJobPostingText();

            console.log("Extracted Job Text:");
            console.log(jobText);

            sendResponse({
                success: true,
                content: jobText,
                pageUrl: window.location.href,
                platform: detectPlatform()
            });
        }

        return true;
    }
);


// Detect which platform the user is browsing
function detectPlatform() {

    const hostname = window.location.hostname;

    if (hostname.includes("linkedin.com")) {
        return "linkedin";
    }

    if (hostname.includes("naukri.com")) {
        return "naukri";
    }

    if (hostname.includes("indeed.com")) {
        return "indeed";
    }

    return "unknown";
}