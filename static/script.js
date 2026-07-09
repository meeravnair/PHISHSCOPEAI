/**
 * PhishScope AI Dashboard - Script Utility
 * Developed By: Meera V Nair
 * GitHub: https://github.com/meeravnair
 *
 * Implements form validation, active load animations, and dashboard elements.
 */

document.addEventListener("DOMContentLoaded", () => {
    const scanForm = document.getElementById("scanForm");
    const loader = document.getElementById("loader");
    const btnScan = document.getElementById("btnScan");

    // Display loader and disable scan button upon submission
    if (scanForm) {
        scanForm.addEventListener("submit", (e) => {
            // Get URL value
            const urlInput = scanForm.querySelector("input[name='url']");
            if (!urlInput || !urlInput.value.trim()) {
                e.preventDefault();
                alert("Please enter a valid URL to proceed.");
                return;
            }

            // Show loader animation
            loader.style.display = "flex";
            
            // Disable button
            btnScan.disabled = true;
            btnScan.style.opacity = "0.7";
            btnScan.style.cursor = "not-allowed";
            btnScan.querySelector(".btn-text").textContent = "Auditing Link...";
        });
    }
});
