// ✅ دالة لجلب CSRF token من meta tag
function getCsrfToken() {
    return document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || ''
}

document.getElementById("sendBtn").addEventListener("click", async () => {
    const email = document.getElementById("email").value
    const msg = document.getElementById("msg")
    const csrfToken = getCsrfToken()

    msg.innerText = "Sending..."
    msg.style.color = "#666"

    try {
        const res = await fetch("/api/reset-2fa", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-CSRF-Token": csrfToken
            },
            body: JSON.stringify({ email })
        })

        const data = await res.json()
        
        // ✅ نفس الرسالة للكل
        msg.innerText = data.message || data.error || "If email exists, reset link will be sent"
        msg.style.color = res.ok ? "#4CAF50" : "#f44336"
        
    } catch (e) {
        console.error("Reset 2FA error:", e)
        msg.innerText = "Server error"
        msg.style.color = "#f44336"
    }
})