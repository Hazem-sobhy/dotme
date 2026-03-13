// ✅ دالة لجلب CSRF token من meta tag
function getCsrfToken() {
    return document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || ''
}

document.getElementById("sendBtn").addEventListener("click", async () => {
    const email = document.getElementById("email").value
    const msg = document.getElementById("msg")
    const csrfToken = getCsrfToken()

    msg.innerText = "Sending..."

    try {
        const res = await fetch("/api/forgot-password", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-CSRF-Token": csrfToken
            },
            body: JSON.stringify({ email })
        })

        const data = await res.json()
        msg.innerText = data.message || data.error
    } catch (e) {
        console.error("Forgot password error:", e)
        msg.innerText = "Server error"
    }
})