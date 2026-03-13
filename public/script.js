/* ================= LOAD PROFILE ================= */

async function load() {

    showLoading()

    const username = window.location.pathname.replace("/", "")

    /* الصفحة الرئيسية */
    if (!username) {
        showWelcomeScreen()
        hideLoading()
        return
    }

    /* تجاهل api و admin */
    if (username.startsWith('api/') || username.startsWith('admin/')) {
        hideLoading()
        return
    }

    try {
        // 1️⃣ جلب بيانات البروفايل
        const profileRes = await fetch("/api/profile/" + username)

        if (!profileRes.ok) {
            throw new Error("User not found")
        }

        const profileData = await profileRes.json()
        
        // 2️⃣ جلب الثيم والتخصيصات
        const themeRes = await fetch(`/api/profile/${username}/theme`)
        const themeData = await themeRes.json()
        
        // 3️⃣ دمج البيانات
        const finalData = {
            ...profileData,
            theme: themeData.theme,
            custom_theme: themeData.custom_theme
        }
        
        renderProfile(finalData)

    } catch (err) {
        console.error("Profile load error:", err)
        document.body.innerHTML = `
            <div style="text-align: center; padding: 50px;">
                <h2>User not found</h2>
                <p>The profile you're looking for doesn't exist.</p>
                <a href="/" style="color: #4CAF50;">Go to home</a>
            </div>
        `
    } finally {
        hideLoading()
    }
}

/* ================= RENDER PROFILE ================= */

function renderProfile(data) {

    /* ================= THEME ================= */
    if (data.theme) {
        document.body.className = data.theme
    }

    /* ================= PROFILE ================= */

    document.getElementById("name").innerText =
        data.profile?.name || window.location.pathname.replace("/", "")

    document.getElementById("title").innerText =
        data.profile?.career || ""

    document.getElementById("bio").innerText =
        data.profile?.bio || ""

    /* ================= PROFILE IMAGE ================= */
    if (data.profile?.image_url) {
        document.getElementById("profile").src = data.profile.image_url
    }

    /* ================= BACKGROUND ================= */
    if (data.profile?.background_url) {
        document.getElementById("background").src = data.profile.background_url
    }

    /* ================= PHONE ================= */
    const phoneBtn = document.getElementById("phoneBtn")
    if (data.profile?.phone) {
        phoneBtn.href = "tel:" + data.profile.phone
        phoneBtn.style.display = "flex"
        phoneBtn.setAttribute('data-tooltip', 'Call')
    } else {
        phoneBtn.style.display = "none"
    }

    /* ================= EMAIL ================= */
    const emailBtn = document.getElementById("emailBtn")
    const email = data.profile?.email || data.profile?.contact_email
    if (email) {
        emailBtn.href = "mailto:" + email
        emailBtn.style.display = "flex"
        emailBtn.setAttribute('data-tooltip', 'Email')
    } else {
        emailBtn.style.display = "none"
    }

    /* ================= LINKS ================= */
    const container = document.getElementById("links")
    container.innerHTML = ""

    if (!data.profile?.name && data.links.length === 0) {
        showWelcomeScreen()
    } 
    else if (data.links.length === 0) {
        showEmptyState()
    } else {
        data.links.forEach(link => {
            const el = document.createElement("a")
            
            el.href = link.url
            el.target = "_blank"
            el.rel = "noopener noreferrer"
            el.className = "link"
            
            el.innerHTML = `
                <img src="${getIcon(link.name)}" alt="${link.name} icon" loading="lazy">
                <span>${escapeHtml(link.name)}</span>
            `

            container.appendChild(el)
        })
    }

    const username = window.location.pathname.slice(1)
    document.title = `${data.profile?.name || username} | Taplink`
    
    // ✅ تطبيق التخصيصات بعد تحميل كل حاجة
    if (data.custom_theme) {
        applyCustomizations(data.custom_theme)
    }
    
    initTooltips()
    prefetchLinks()
}

/* ================= WELCOME SCREEN (Check if logged in) ================= */
function showWelcomeScreen() {
    const container = document.querySelector(".container")
    const welcomeScreen = document.getElementById("welcome-screen")
    
    if (welcomeScreen) {
        container.style.display = "none"
        welcomeScreen.style.display = "flex"
    } else {
        container.innerHTML = `
        <div class="welcome-screen" id="welcome-screen">
            <div class="minimal-card">
                <div class="minimal-logo">
                    <svg width="48" height="48" viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
                        <circle cx="24" cy="24" r="20" stroke="#4CAF50" stroke-width="2" stroke-dasharray="4 4"/>
                        <circle cx="24" cy="24" r="8" fill="#4CAF50"/>
                    </svg>
                </div>

                <h1 class="minimal-title">DotMe</h1>
                <p class="minimal-subtitle">One link for everything you are</p>

                <div class="minimal-buttons">
                    <a href="/admin/dashboard.html" class="minimal-btn-primary">
                        Create your page
                    </a>
                    <a href="/admin/dashboard.html" class="minimal-btn-secondary">
                        Sign in
                    </a>
                </div>

                <p class="minimal-footer">
                    Free • Customizable • No ads
                </p>
            </div>
        </div>
        `
    }
}


/* ================= APPLY CUSTOMIZATIONS ================= */

function applyCustomizations(custom) {
    
    // التأكد من أن custom هو object
    let t = custom
    if (typeof custom === 'string') {
        try {
            t = JSON.parse(custom)
        } catch (e) {
            console.error("Failed to parse custom theme:", e)
            return
        }
    }
    
    // إنشاء style element للتخصيصات
    let styleEl = document.getElementById('custom-theme-styles')
    if (!styleEl) {
        styleEl = document.createElement('style')
        styleEl.id = 'custom-theme-styles'
        document.head.appendChild(styleEl)
    }
    
    // بناء CSS مع !important
    let customCSS = ''
    
    // الألوان الأساسية
    if (t.primaryColor) {
        customCSS += `
            .circle-btn i { color: ${t.primaryColor} !important; }
            .circle-btn:hover { background: ${t.primaryColor} !important; }
            .save-btn { background: ${t.primaryColor} !important; }
            .link:hover span { color: ${t.primaryColor} !important; }
            .link:hover img { border-color: ${t.primaryColor} !important; }
            .qr-share { background: ${t.primaryColor} !important; }
        `
    }
    
    // لون الخلفية
    if (t.bgColor) {
        customCSS += `
            body { background-color: ${t.bgColor} !important; }
            .container { background-color: ${t.bgColor} !important; }
            body.light .container { background-color: ${t.bgColor} !important; }
            body.dark .container { background-color: ${t.bgColor} !important; }
        `
    }
    
    // لون النص
    if (t.textColor) {
        customCSS += `
            body, h1, #title, .bio, .link span { color: ${t.textColor} !important; }
            body.light h1, body.dark h1 { color: ${t.textColor} !important; }
        `
    }
    
    // Border Radius
    if (t.borderRadius) {
        customCSS += `
            .link img { border-radius: ${t.borderRadius}px !important; }
            .save-btn { border-radius: ${t.borderRadius}px !important; }
        `
    }
    
    // Font Family
    if (t.fontFamily) {
        customCSS += `
            body, h1, #title, .bio, .link span, .save-btn, .circle-btn i { font-family: ${t.fontFamily} !important; }
        `
    }
    
    // Button Style
    if (t.buttonStyle === 'square') {
        customCSS += `
            .save-btn, .link img { border-radius: 0 !important; }
        `
    } else if (t.buttonStyle === 'pill') {
        customCSS += `
            .save-btn, .link img { border-radius: 50px !important; }
        `
    } else if (t.buttonStyle === 'outline') {
        customCSS += `
            .save-btn { 
                background: transparent !important; 
                border: 2px solid ${t.primaryColor || '#4CAF50'} !important; 
                color: ${t.primaryColor || '#4CAF50'} !important; 
            }
            .save-btn:hover { 
                background: ${t.primaryColor || '#4CAF50'} !important; 
                color: white !important; 
            }
        `
    } else if (t.buttonStyle === 'glass') {
        customCSS += `
            .save-btn { 
                background: rgba(255,255,255,0.2) !important; 
                backdrop-filter: blur(10px) !important; 
                border: 1px solid rgba(255,255,255,0.3) !important; 
                color: ${t.textColor || 'white'} !important; 
            }
        `
    } else if (t.buttonStyle === 'neon') {
        customCSS += `
            .save-btn { 
                background: transparent !important; 
                border: 2px solid ${t.primaryColor || '#0ff'} !important; 
                color: ${t.primaryColor || '#0ff'} !important; 
                box-shadow: 0 0 10px ${t.primaryColor || '#0ff'} !important;
            }
            .save-btn:hover { 
                background: ${t.primaryColor || '#0ff'} !important; 
                color: #000 !important; 
            }
        `
    }
    
    // تطبيق CSS المخصص
    styleEl.textContent = customCSS
}

/* ================= LOADING STATES ================= */

function showLoading() {
    const container = document.getElementById("links")
    if (container) {
        container.innerHTML = '<div class="spinner"></div>'
    }
}

function hideLoading() {}

/* ================= EMPTY STATES ================= */

function showEmptyState() {
    const container = document.getElementById("links")
    if (container) {
        container.innerHTML = '<div class="no-links-message">No links yet</div>'
    }
}

/* ================= TOOLTIPS ================= */

function initTooltips() {
    document.querySelectorAll('.circle-btn, .save-btn, .icon-btn').forEach(btn => {
        if (btn.id === 'phoneBtn' && btn.style.display !== 'none') 
            btn.setAttribute('data-tooltip', 'Call')
        if (btn.id === 'emailBtn' && btn.style.display !== 'none') 
            btn.setAttribute('data-tooltip', 'Email')
        if (btn.id === 'saveContactBtn') 
            btn.setAttribute('data-tooltip', 'Save to contacts')
        if (btn.classList.contains('icon-btn') && btn.id === 'menuBtn') 
            btn.setAttribute('data-tooltip', 'Menu')
        if (btn.classList.contains('icon-btn') && btn.id === 'shareBtn') 
            btn.setAttribute('data-tooltip', 'Share')
    })
}

/* ================= HELPER FUNCTIONS ================= */

function escapeHtml(unsafe) {
    return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;")
}

function getIcon(name) {
    name = name.toLowerCase().trim()

    const icons = {
        "whatsapp": "icons/whatsapp.png",
        "linkedin": "icons/linkedin.png",
        "gmail": "icons/gmail.png",
        "telegram": "icons/telegram.png",
        "github": "icons/github.png",
        "facebook": "icons/facebook.png",
        "instagram": "icons/instagram.png",
        "twitter": "icons/twitter.png",
        "youtube": "icons/youtube.png",
        "tiktok": "icons/tiktok.png",
        "snapchat": "icons/snapchat.png",
        "pinterest": "icons/pinterest.png",
        "discord": "icons/discord.png",
        "spotify": "icons/spotify.png",
        "twitch": "icons/twitch.png"
    }

    return icons[name] || "icons/link.png"
}

/* ================= SAVE CONTACT ================= */

function saveContact() {
    const name = document.getElementById("name").innerText
    const phoneBtn = document.getElementById("phoneBtn")
    
    if (!phoneBtn || !phoneBtn.href) {
        showToast("No phone number available")
        return
    }
    
    const phone = phoneBtn.href.replace("tel:", "")

    const vcard = `BEGIN:VCARD
VERSION:3.0
FN:${name}
TEL:${phone}
END:VCARD`

    const blob = new Blob([vcard], { type: "text/vcard" })
    const link = document.createElement("a")
    link.href = URL.createObjectURL(blob)
    link.download = "contact.vcf"
    link.click()
    
    setTimeout(() => URL.revokeObjectURL(link.href), 100)
    showToast("Contact saved!")
}

/* ================= MENU ================= */

function toggleMenu() {
    const menu = document.getElementById("menuDropdown")
    const share = document.getElementById("shareMenu")
    
    share.style.display = "none"
    menu.style.display = menu.style.display === "block" ? "none" : "block"
}

function toggleShare() {
    const share = document.getElementById("shareMenu")
    const menu = document.getElementById("menuDropdown")
    
    menu.style.display = "none"
    share.style.display = share.style.display === "block" ? "none" : "block"
}

/* ================= COPY LINK ================= */

function copyLink() {
    navigator.clipboard.writeText(window.location.href)
        .then(() => showToast("Link copied!"))
        .catch(() => showToast("Failed to copy"))
}

/* ================= TOAST ================= */

function showToast(message) {
    let toast = document.getElementById("toast")

    if (!toast) {
        toast = document.createElement("div")
        toast.id = "toast"
        document.body.appendChild(toast)
    }

    toast.innerText = message
    toast.classList.add("show")

    setTimeout(() => {
        toast.classList.remove("show")
    }, 2000)
}

/* ================= QR ================= */

function showQR() {
    const modal = document.getElementById("qrModal")
    const img = document.getElementById("qrImage")
    
    img.src = "https://api.qrserver.com/v1/create-qr-code/?size=250x250&data=" +
        encodeURIComponent(window.location.href)
    
    modal.style.display = "flex"
}

function closeQR() {
    document.getElementById("qrModal").style.display = "none"
}

async function shareQR() {
    const img = document.getElementById("qrImage")
    
    try {
        const response = await fetch(img.src)
        const blob = await response.blob()
        const file = new File([blob], "profile-qr.png", { type: "image/png" })

        if (navigator.share && navigator.canShare && navigator.canShare({ files: [file] })) {
            await navigator.share({
                files: [file],
                title: "My Profile QR"
            })
        } else {
            const link = document.createElement("a")
            link.href = URL.createObjectURL(blob)
            link.download = "profile-qr.png"
            link.click()
            setTimeout(() => URL.revokeObjectURL(link.href), 100)
        }
    } catch (e) {
        console.error("Share QR error:", e)
        showToast("Could not share QR")
        window.open(img.src, '_blank')
    }
}

/* ================= NATIVE SHARE ================= */

function nativeShare() {
    if (navigator.share) {
        navigator.share({
            title: document.getElementById("name").innerText || "My Profile",
            url: window.location.href
        }).catch(() => copyLink())
    } else {
        copyLink()
    }
}

/* ================= CLOSE MENUS ================= */

document.addEventListener("click", function(e) {
    const menu = document.getElementById("menuDropdown")
    const share = document.getElementById("shareMenu")
    
    if (!e.target.closest(".top-bar")) {
        menu.style.display = "none"
        share.style.display = "none"
    }
})

/* ================= PERFORMANCE OPTIMIZATIONS ================= */

function prefetchLinks() {
    const links = document.querySelectorAll('.link')
    links.forEach(link => {
        link.addEventListener('mouseenter', () => {
            const prefetch = document.createElement('link')
            prefetch.rel = 'prefetch'
            prefetch.href = link.href
            document.head.appendChild(prefetch)
        }, { once: true })
    })
}

function saveToLocalStorage(key, data) {
    try {
        localStorage.setItem(key, JSON.stringify({
            data,
            timestamp: Date.now()
        }))
    } catch (e) {
        console.error('Storage error:', e)
    }
}

function getFromLocalStorage(key, maxAge = 300000) { // 5 دقائق افتراضياً
    try {
        const item = JSON.parse(localStorage.getItem(key))
        if (item && (Date.now() - item.timestamp < maxAge)) {
            return item.data
        }
    } catch (e) {}
    return null
}

/* ================= KEYBOARD SHORTCUTS ================= */

document.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 's') {
        e.preventDefault()
        saveContact()
    }
    
    if (e.key === 'Escape') {
        closeQR()
    }
})

/* ================= REVEAL ON SCROLL ================= */

document.querySelectorAll('.link, .circle-btn').forEach(el => {
    el.classList.add('reveal')
})

const revealObserver = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
        if (entry.isIntersecting) {
            entry.target.classList.add('active')
        }
    })
})

document.querySelectorAll('.reveal').forEach(el => revealObserver.observe(el))

/* ================= FONT AWESOME FALLBACK ================= */

function checkFontAwesome() {
    const testIcon = document.createElement('i')
    testIcon.className = 'fas fa-phone'
    document.body.appendChild(testIcon)
    
    setTimeout(() => {
        const style = window.getComputedStyle(testIcon)
        const fontFamily = style.getPropertyValue('font-family')
        
        if (!fontFamily.includes('Font Awesome')) {
            console.warn('Font Awesome not loaded, using fallback')
            document.querySelectorAll('.icon-btn i, .circle-btn i').forEach(icon => {
                if (icon.classList.contains('fa-ellipsis-v')) {
                    icon.outerHTML = '<span style="font-size:24px;">⋮</span>'
                } else if (icon.classList.contains('fa-share-alt')) {
                    icon.outerHTML = '<span style="font-size:20px;">↗️</span>'
                } else if (icon.classList.contains('fa-phone')) {
                    icon.outerHTML = '<span style="font-size:24px;">📞</span>'
                } else if (icon.classList.contains('fa-envelope')) {
                    icon.outerHTML = '<span style="font-size:24px;">✉️</span>'
                }
            })
        }
        testIcon.remove()
    }, 100)
}

/* ================= INIT ================= */

document.addEventListener("DOMContentLoaded", () => {
    // Menu buttons
    document.getElementById("menuBtn")?.addEventListener("click", toggleMenu)
    document.getElementById("shareBtn")?.addEventListener("click", toggleShare)
    
    // Share menu buttons
    document.getElementById("copyLinkBtn")?.addEventListener("click", copyLink)
    document.getElementById("qrBtn")?.addEventListener("click", showQR)
    document.getElementById("nativeShareBtn")?.addEventListener("click", nativeShare)
    
    // Save contact
    document.getElementById("saveContactBtn")?.addEventListener("click", saveContact)
    document.getElementById("saveContactBtn")?.setAttribute('data-tooltip', 'Save to contacts')
    
    // QR modal buttons
    document.getElementById("shareQrBtn")?.addEventListener("click", shareQR)
    document.getElementById("closeQrBtn")?.addEventListener("click", closeQR)
    
    // Load profile with cache
    const cachedData = getFromLocalStorage('profile_' + window.location.pathname.replace("/", ""))
    if (cachedData) {
        renderProfile(cachedData)
    } else {
        load()
    }
    
    initTooltips()
    checkFontAwesome()
})