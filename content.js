(() => {
    let clone = document.body.cloneNode(true);
    let garbageElements = clone.querySelectorAll('footer, header, nav, [class*="footer"], [class*="disclaimer"], [class*="warning"]');
    garbageElements.forEach(el => el.remove());

    let mainContentText = "";
    const descriptionSelectors = ['[itemprop="description"]', '.job-desc', '.job-description', '#jobDescriptionText', '[data-automation="jobDescription"]'];
    
    for (let selector of descriptionSelectors) {
        let el = clone.querySelector(selector);
        if (el && el.innerText.trim() !== "") { mainContentText = el.innerText; break; }
    }
    if (mainContentText === "") { mainContentText = clone.innerText; }

    // THE SANITIZER
    const lowerText = mainContentText.toLowerCase();
    const cutoffPhrases = ["beware of imposters", "naukri.com does not promise", "does not charge any fee", "fraud alert", "disclaimer:", "naukri never asks"];

    let earliestCutoff = mainContentText.length;
    for (let phrase of cutoffPhrases) {
        let index = lowerText.indexOf(phrase);
        if (index !== -1 && index < earliestCutoff) earliestCutoff = index;
    }
    mainContentText = mainContentText.substring(0, earliestCutoff);

    const emailRegex = /([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9_-]+)/gi;
    const foundEmails = mainContentText.match(emailRegex); 
    let extractedEmail = foundEmails ? foundEmails[0] : "No email found";

    let extractedCompany = "Unknown";
    const scripts = document.querySelectorAll('script[type="application/ld+json"]');
    for (let script of scripts) {
        try {
            const data = JSON.parse(script.innerText);
            let jobData = Array.isArray(data) ? data.find(item => item['@type'] === 'JobPosting') : (data['@type'] === 'JobPosting' ? data : null);
            if (jobData && jobData.hiringOrganization && jobData.hiringOrganization.name) {
                extractedCompany = jobData.hiringOrganization.name; break;
            }
        } catch (e) {}
    }

    if (extractedCompany === "Unknown") {
        const titleParts = document.title.split('-');
        if (titleParts.length > 1) extractedCompany = titleParts[1].trim(); 
    }
    if (extractedCompany === "Unknown" || extractedCompany.toLowerCase().includes("job listings")) {
        const selectorsToTry = ['.jd-header-comp-name a', '.company-name'];
        for (let sel of selectorsToTry) {
            let el = document.querySelector(sel);
            if (el && el.innerText.trim() !== "") { extractedCompany = el.innerText.trim(); break; }
        }
    }

    return { company: extractedCompany, email: extractedEmail, fullText: mainContentText };
})();