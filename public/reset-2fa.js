// ✅ دالة لجلب CSRF token من meta tag
function getCsrfToken() {
    const meta = document.querySelector('meta[name="csrf-token"]')
    if (!meta) {
        console.warn('CSRF token meta tag not found')
        return ''
    }
    const token = meta.getAttribute('content')
    console.log('CSRF Token found:', token ? '✅' : '❌')
    return token || ''
}

const params = new URLSearchParams(window.location.search)
const token = params.get("token")

async function load() {
    const csrfToken = getCsrfToken()
    const errorEl = document.getElementById("error")
    const qrEl = document.getElementById("qr")
    const loadingEl = document.getElementById("loading")
    const messageEl = document.getElementById("message")

    // ✅ التحقق من وجود التوكن
    if (!token || token.length < 20) {
        if (loadingEl) loadingEl.style.display = 'none'
        errorEl.innerText = "Invalid or expired link"
        return
    }

    try {
        console.log('Sending request with token:', token.substring(0, 10) + '...')
        
        const res = await fetch("/api/new-2fa", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-CSRF-Token": csrfToken
            },
            body: JSON.stringify({ token })
        })

        const data = await res.json()
        console.log('Response:', data)

        if (loadingEl) loadingEl.style.display = 'none'

        if (!res.ok) {
            throw new Error(data.error || "Failed to reset 2FA")
        }

        if (data.qr) {
            qrEl.src = data.qr
            qrEl.style.display = 'block'
            errorEl.innerText = ''
            if (messageEl) messageEl.innerText = 'Scan the QR code with Google Authenticator'
        } else {
            errorEl.innerText = data.error || "Invalid or expired link"
        }
    } catch (e) {
        console.error("Reset 2FA error:", e)
        if (loadingEl) loadingEl.style.display = 'none'
        errorEl.innerText = e.message || "Server error. Please try again later."
    }
}

// شغل load لما الصفحة تتحمل
document.addEventListener('DOMContentLoaded', load)