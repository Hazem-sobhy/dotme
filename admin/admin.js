//console.log("🔥 admin.js loaded successfully (JWT CSRF Edition)")//

// ✅ المتغيرات في الذاكرة فقط (مش في localStorage)
let inMemoryToken = null
let csrfToken = null
let username = null
let userId = null
let currentProfileImage = ""
let currentBackgroundImage = ""

// ✅ دالة لجلب CSRF token من الذاكرة (وليس من meta tag)
function getCsrfToken() {
    return csrfToken || ""
}

// ✅ دالة لاستعادة الجلسة من الـ refresh token
async function restoreSession() {
    try {
        const csrf = getCsrfToken()

        //console.log("Restoring session with CSRF:", csrf ? "OK" : "Missing")//

        const res = await fetch("/api/refresh-token", {
            method: "POST",
            credentials: "include",
            headers: {
                "X-CSRF-Token": csrf,
                "Content-Type": "application/json"
            }
        })

        if (!res.ok) {
            console.error("Session restore failed:", res.status)
            return false
        }

        const data = await res.json()
        inMemoryToken = data.token
        csrfToken = data.csrfToken

        // ✅ جلب البيانات الشخصية للحصول على username
        const profileRes = await fetch("/api/admin/profile", {
            headers: {
                Authorization: "Bearer " + inMemoryToken,
                "X-CSRF-Token": csrfToken
            }
        })

        if (!profileRes.ok) {
            console.error("Profile fetch failed:", profileRes.status)
            return false
        }

        const profileData = await profileRes.json()
        username = profileData.profile?.username || null  // ✅ تحديث username

        //console.log("✅ Session restored successfully, username:", username)//
        return true

    } catch (e) {
        console.error("Session restore error:", e)
        return false
    }
}

/* ================= BUTTON LOADING STATE ================= */

function setButtonLoading(buttonId, isLoading) {
    const btn = document.getElementById(buttonId)
    if (!btn) return
    
    if (isLoading) {
        btn.disabled = true
        btn.dataset.originalText = btn.innerText
        btn.innerText = "Loading..."
    } else {
        btn.disabled = false
        btn.innerText = btn.dataset.originalText || "Submit"
    }
}

/* ================= API WRAPPER (محمي بـ CSRF) ================= */

async function api(url, options = {}) {
    if (!inMemoryToken) {
        const restored = await restoreSession()
        if (!restored) {
            logout()
            throw new Error("No token")
        }
    }

    const csrf = getCsrfToken()
    const isFormData = options.body instanceof FormData
    
    options.credentials = "include"
    
    options.headers = {
        ...(options.headers || {}),
        "Authorization": "Bearer " + inMemoryToken,
        "X-CSRF-Token": csrf
    }
    
    if (!isFormData) {
        options.headers["Content-Type"] = "application/json"
    }

    let res = await fetch(url, options)
    
    // ✅ لو 401، حاول تجديد التوكن
    if (res.status === 401) {
        try {
            const refreshRes = await fetch("/api/refresh-token", {
                method: "POST",
                credentials: 'include',
                headers: { 
                    "X-CSRF-Token": getCsrfToken(),
                    "Content-Type": "application/json"
                }
            })
            
            if (refreshRes.ok) {
                const data = await refreshRes.json()
                inMemoryToken = data.token
                csrfToken = data.csrfToken // ✅ تحديث csrfToken

                options.headers["Authorization"] = "Bearer " + inMemoryToken
                options.headers["X-CSRF-Token"] = csrfToken

                res = await fetch(url, options)
            } else {
                logout()
                throw new Error("Session expired")
            }
        } catch (e) {
            logout()
            throw new Error("Session expired")
        }
    }
    
    // ✅ لو 403 (CSRF error)، حاول مرة واحدة بس
    if (res.status === 403) {
        const data = await res.json().catch(() => ({}))
        if (data.error && data.error.toLowerCase().includes('csrf')) {
            console.warn("CSRF token error, attempting refresh...")
            // حاول تجديد الـ CSRF token
            try {
                const refreshRes = await fetch("/api/refresh-token", {
                    method: "POST",
                    credentials: 'include',
                    headers: { 
                        "X-CSRF-Token": getCsrfToken(),
                        "Content-Type": "application/json"
                    }
                })
                
                if (refreshRes.ok) {
                    const refreshData = await refreshRes.json()
                    inMemoryToken = refreshData.token
                    csrfToken = refreshData.csrfToken
                    
                    options.headers["Authorization"] = "Bearer " + inMemoryToken
                    options.headers["X-CSRF-Token"] = csrfToken
                    
                    res = await fetch(url, options)
                } else {
                    logout()
                    throw new Error("CSRF token expired")
                }
            } catch (e) {
                logout()
                throw new Error("CSRF token expired")
            }
        } else {
            logout()
            throw new Error("Access denied")
        }
    }
    
    return res
}

/* ================= LINK COUNTER ================= */

async function updateLinkCounter() {
    try {
        const res = await api("/api/dashboard")
        const data = await res.json()
        
        const currentLinks = data.links || 0
        const maxLinks = 23
        const remaining = maxLinks - currentLinks
        
        let counterEl = document.getElementById("linkCounter")
        
        if (!counterEl) {
            const addCard = document.querySelector('.card:has(#addLinkBtn)') || 
                           document.getElementById('addLinkBtn')?.closest('.card')
            
            if (addCard) {
                counterEl = document.createElement('div')
                counterEl.id = 'linkCounter'
                counterEl.style.cssText = `
                    text-align: right;
                    font-size: 12px;
                    margin-bottom: 10px;
                    padding: 4px 8px;
                    border-radius: 20px;
                    background: rgba(0,0,0,0.05);
                `
                addCard.insertBefore(counterEl, document.getElementById('addLinkBtn').parentNode)
            }
        }
        
        if (counterEl) {
            counterEl.innerText = `${currentLinks}/${maxLinks} links used`
            counterEl.style.color = remaining <= 3 ? '#f44336' : '#4CAF50'
        }
        
        const addBtn = document.getElementById("addLinkBtn")
        if (addBtn) {
            addBtn.disabled = currentLinks >= maxLinks
            addBtn.title = currentLinks >= maxLinks ? 'Maximum links reached (23)' : 'Add new link'
        }
    } catch (e) {
        console.error("Link counter error:", e)
    }
}

/* ================= INIT ================= */

document.addEventListener("DOMContentLoaded", async () => {
    // ✅ تأخير بسيط للتأكد من تحميل كل شيء
    await new Promise(r => setTimeout(r, 50))

    const restored = await restoreSession()
    
    if (restored) {
        loadDashboard()
    } else {
        showLogin()
    }
})

/* ================= UI ================= */

function showLogin() {
    document.getElementById("loginBox").style.display = "block"
    document.getElementById("twofaSection").style.display = "none"
    const forgot = document.getElementById("forgotSection")
    if(forgot) forgot.style.display = "none"
    document.getElementById("registerSection").style.display = "none"
    document.getElementById("panel").style.display = "none"
}

function show2FA() {
    document.getElementById("loginBox").style.display = "none"
    document.getElementById("twofaSection").style.display = "block"
    document.getElementById("otp")?.focus()
}

function showPanel() {
    document.getElementById("loginBox").style.display = "none"
    document.getElementById("twofaSection").style.display = "none"
    const forgot = document.getElementById("forgotSection")
    if(forgot) forgot.style.display = "none"
    document.getElementById("registerSection").style.display = "none"
    document.getElementById("panel").style.display = "block"
}

async function login() {
    setButtonLoading("loginBtn", true)
    
    const user = document.getElementById("username").value.trim()
    const password = document.getElementById("password").value

    if (!user || !password) {
        toast("Fill all fields")
        setButtonLoading("loginBtn", false)
        return
    }

    try {
        const res = await fetch("/api/login", {
            method: "POST",
            headers: { 
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ username: user, password }),
            credentials: 'include'
        })

        const result = await res.json()

        if (result.step === "2fa") {
            userId = result.userId
            username = user  // ✅ تحديث username هنا
            show2FA()
            setButtonLoading("loginBtn", false)
            return
        }

        if (result.token) {
            inMemoryToken = result.token
            csrfToken = result.csrfToken
            username = result.username  // ✅ تحديث username من الاستجابة

            // تحميل لوحة التحكم مباشرة
            loadDashboard()
        } else {
            toast(result.error || "Login failed")
        }
    } catch (e) {
        console.error("Login error:", e)
        toast("Server error")
    } finally {
        setButtonLoading("loginBtn", false)
    }
}

async function verify2FA() {
    setButtonLoading("verifyBtn", true)
    
    const code = document.getElementById("otp").value.trim()

    try {
        const res = await fetch("/api/2fa/verify", {
            method: "POST",
            headers: { 
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ userId, code }),
            credentials: 'include'
        })

        const result = await res.json()

        if (result.token) {
            inMemoryToken = result.token
            csrfToken = result.csrfToken
            username = result.username  // ✅ تحديث username من الاستجابة

            // تحميل لوحة التحكم مباشرة
            loadDashboard()
        } else {
            toast(result.error || "Invalid code")
        }
    } catch (e) {
        console.error("2FA error:", e)
        toast("Server error")
    } finally {
        setButtonLoading("verifyBtn", false)
    }
}

/* ================= DASHBOARD ================= */

async function loadDashboard() {
    if (!inMemoryToken) {
        logout()
        return
    }
    
    showPanel()
    await Promise.all([
        loadStats(),
        loadProfile(),
        loadLinks()
    ])
}

/* ================= STATS ================= */

async function loadStats() {
    try {
        const res = await api("/api/dashboard")
        const data = await res.json()

        document.getElementById("viewsCount").innerText = data.views || 0
        document.getElementById("linksCount").innerText = data.links || 0
        document.getElementById("clicksCount").innerText = data.clicks || 0
    } catch (e) {
        console.error("Stats error", e)
    }
}

/* ================= ANALYTICS ================= */

async function loadAnalytics() {
    try {
        const res = await api("/api/dashboard")
        const data = await res.json()

        const canvas = document.getElementById("viewsChart")
        if (!canvas) return
        const ctx = canvas.getContext("2d")
        if (!ctx) return

        if (window.chart) window.chart.destroy()

        window.chart = new Chart(ctx, {
            type: "bar",
            data: {
                labels: ["Views", "Clicks", "Links"],
                datasets: [{
                    label: "Analytics",
                    data: [data.views || 0, data.clicks || 0, data.links || 0],
                    backgroundColor: [
                        'rgba(76, 175, 80, 0.5)',
                        'rgba(33, 150, 243, 0.5)',
                        'rgba(255, 152, 0, 0.5)'
                    ],
                    borderColor: [
                        '#4CAF50',
                        '#2196F3',
                        '#FF9800'
                    ],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: { stepSize: 1 }
                    }
                }
            }
        })
    } catch (e) {
        console.error("Chart error", e)
    }
}

/* ================= PROFILE ================= */

async function uploadImage(file) {
    try {
        if (!file) {
            throw new Error("No file selected")
        }

        if (file.size > 5 * 1024 * 1024) {
            throw new Error("File too large. Maximum size is 5MB")
        }

        const validTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp']
        if (!validTypes.includes(file.type)) {
            throw new Error("Invalid file type. Only images are allowed (JPEG, PNG, GIF, WEBP)")
        }

        const formData = new FormData()
        formData.append("image", file)

        console.log(`📤 Uploading image: ${file.name} (${(file.size / 1024).toFixed(2)} KB)`)

        const res = await api("/api/upload", {
            method: "POST",
            body: formData
        })

        if (!res.ok) {
            const errorData = await res.json().catch(() => ({ error: "Upload failed" }))
            throw new Error(errorData.error || "Upload failed")
        }

        const data = await res.json()
        console.log("✅ Upload successful:", data.url)
        return data.url
    } catch (e) {
        console.error("❌ Upload error details:", e)
        toast(e.message)
        throw e
    }
}

async function saveProfile() {
    setButtonLoading("saveProfileBtn", true)
    
    try {
        const name = document.getElementById("profileName").value.trim()
        const bio = document.getElementById("bio").value.trim()
        const career = document.getElementById("career").value.trim()
        const phone = document.getElementById("phone").value.trim()

        let image_url = currentProfileImage
        let background_url = currentBackgroundImage

        const profileFile = document.getElementById("profileImage").files[0]
        const bgFile = document.getElementById("backgroundImage").files[0]

        if (profileFile) {
            toast("Uploading profile image...")
            image_url = await uploadImage(profileFile)
        }

        if (bgFile) {
            toast("Uploading background image...")
            background_url = await uploadImage(bgFile)
        }

        await api("/api/profile", {
            method: "PUT",
            body: JSON.stringify({
                name,
                bio,
                career,
                phone,
                image_url,
                background_url
            })
        })

        // تحديث الصور الحالية بعد الحفظ الناجح
        if (profileFile) currentProfileImage = image_url
        if (bgFile) currentBackgroundImage = background_url

        toast("Profile updated successfully")
    } catch (e) {
        console.error("Save profile error:", e)
        toast(e.message || "Failed to save profile")
    } finally {
        setButtonLoading("saveProfileBtn", false)
    }
}

async function loadProfile() {
    try {
        const res = await api("/api/admin/profile")
        const data = await res.json()

        const profileName = document.getElementById("profileName")
        const bio = document.getElementById("bio")
        const career = document.getElementById("career")
        const phone = document.getElementById("phone")

        if (profileName) profileName.value = data.profile?.name || ""
        if (bio) bio.value = data.profile?.bio || ""
        if (career) career.value = data.profile?.career || ""
        if (phone) phone.value = data.profile?.phone || ""


        currentProfileImage = data.profile?.image_url || ""
        currentBackgroundImage = data.profile?.background_url || ""

    } catch (e) {
        console.error("Profile error", e)
    }
}

/* ================= LINKS ================= */

async function loadLinks() {
    try {
        const res = await api("/api/admin/profile")
        const data = await res.json()

        const container = document.getElementById("links")
        container.innerHTML = ""

        data.links.forEach(link => {
            const tr = document.createElement("tr")
            
            const tdName = document.createElement("td")
            tdName.textContent = link.name
            
            const tdAction = document.createElement("td")
            const deleteBtn = document.createElement("button")
            deleteBtn.textContent = "Delete"
            deleteBtn.className = "delete"
            
            deleteBtn.addEventListener("click", () => deleteLink(link.id))
            
            tdAction.appendChild(deleteBtn)
            tr.appendChild(tdName)
            tr.appendChild(tdAction)
            
            container.appendChild(tr)
        })
        
        await updateLinkCounter()
        
    } catch (e) {
        console.error("Load links error", e)
        toast("Failed to load links")
    }
}

async function add() {
    const name = document.getElementById("name").value.trim()
    const url = document.getElementById("url").value.trim()

    if (!name || !url) {
        toast("Fill all fields")
        return
    }

    const counterEl = document.getElementById("linkCounter")
    if (counterEl && counterEl.innerText.includes('23/23')) {
        toast("Maximum 23 links reached!")
        return
    }

    try {
        new URL(url)
    } catch {
        toast("Invalid URL - must include http:// or https://")
        return
    }

    try {
        await api("/api/link", {
            method: "POST",
            body: JSON.stringify({ name, url })
        })

        document.getElementById("name").value = ""
        document.getElementById("url").value = ""
        
        await loadLinks()
        toast("Link added successfully")
    } catch (e) {
        if (e.message?.includes("Maximum")) {
            toast(e.message)
        } else {
            console.error("Add link error", e)
            toast("Failed to add link")
        }
    }
}

async function deleteLink(id) {
    if (!confirm("Are you sure you want to delete this link?")) return

    try {
        await api("/api/link/" + id, {
            method: "DELETE"
        })
        
        await loadLinks()
        toast("Link deleted")
    } catch (e) {
        console.error("Delete link error", e)
        toast("Failed to delete link")
    }
}

/* ================= LOGOUT ================= */

async function logout() {
    try {
        if (inMemoryToken) {
            await fetch("/api/logout", {
                method: "POST",
                credentials: 'include',
                headers: {
                    "Authorization": "Bearer " + inMemoryToken,
                    "X-CSRF-Token": getCsrfToken(),
                    "Content-Type": "application/json"
                }
            })
        }
    } catch (e) {
        console.error("Logout error:", e)
    }
    
    inMemoryToken = null
    csrfToken = null
    username = null
    userId = null
    currentProfileImage = ""
    currentBackgroundImage = ""
    
    showLogin()
}

/* ================= AUTH UI ================= */

function showForgot() {
    document.getElementById("loginBox").style.display = "none"
    document.getElementById("forgotSection").style.display = "block"
}

function showRegister() {
    document.getElementById("loginBox").style.display = "none"
    document.getElementById("registerSection").style.display = "block"
}

/* ================= REGISTER ================= */

async function register() {
    setButtonLoading("registerSubmitBtn", true)
    
    const username = document.getElementById("regUsername").value.trim()
    const email = document.getElementById("regEmail").value.trim()
    const password = document.getElementById("regPassword").value

    try {
        const res = await fetch("/api/register", {
            method: "POST",
            headers: { 
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ username, email, password })
        })

        const result = await res.json()

        if (result.qr) {
            document.getElementById("registerSection").innerHTML = `
                <h2>Scan QR Code</h2>
                <p>Scan this with Google Authenticator app</p>
                <img src="${result.qr}" style="width:200px; margin:20px auto; display:block;">
                <p style="color: #666;">After scanning, click Done to login</p>
                <button id="doneBtn" class="primary">Done</button>
            `
            
            document.getElementById("doneBtn").addEventListener("click", () => {
                showLogin()
            })
        } else {
            toast(result.error || "Registration failed")
        }
    } catch (e) {
        console.error("Register error", e)
        toast("Server error during registration")
    } finally {
        setButtonLoading("registerSubmitBtn", false)
    }
}

/* ================= RESET PASSWORD ================= */

async function requestReset() {
    setButtonLoading("resetBtn", true)
    
    const email = document.getElementById("resetEmail").value.trim()

    if (!email) {
        toast("Email required")
        setButtonLoading("resetBtn", false)
        return
    }

    try {
        const res = await fetch("/api/forgot-password", {
            method: "POST",
            headers: { 
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ email })
        })

        const result = await res.json()
        toast(result.message || result.error || "Check your email")
    } catch (e) {
        console.error("Reset error", e)
        toast("Server error")
    } finally {
        setButtonLoading("resetBtn", false)
    }
}

/* ================= TOAST ================= */

function toast(msg) {
    const t = document.getElementById("toast")
    t.innerText = msg
    t.style.display = "block"
    t.style.opacity = "1"

    setTimeout(() => {
        t.style.opacity = "0"
        setTimeout(() => {
            t.style.display = "none"
        }, 300)
    }, 2700)
}

/* ================= EVENT LISTENERS ================= */
document.addEventListener("DOMContentLoaded", () => {
    
    document.getElementById("openProfileBtn")?.addEventListener("click", () => {
        if (username) {
            // التأكد من أن username ليس فارغاً
            const profileUrl = "/" + username
            console.log("Opening profile URL:", profileUrl)
            window.open(profileUrl, "_blank")
        } else {
            toast("Please login first")
        }
    })
    
    document.getElementById("loginBtn")?.addEventListener("click", login)
    document.getElementById("password")?.addEventListener("keypress", (e) => {
        if (e.key === "Enter") login()
    })
    
    document.getElementById("verifyBtn")?.addEventListener("click", verify2FA)
    document.getElementById("otp")?.addEventListener("keypress", (e) => {
        if (e.key === "Enter") verify2FA()
    })
    
    document.getElementById("logoutBtn")?.addEventListener("click", logout)
    document.getElementById("addLinkBtn")?.addEventListener("click", add)
    document.getElementById("saveProfileBtn")?.addEventListener("click", saveProfile)
    document.getElementById("registerSubmitBtn")?.addEventListener("click", register)
    document.getElementById("resetBtn")?.addEventListener("click", requestReset)

    // روابط التنقل
    const forgotBtn = document.getElementById("forgotBtn")
    if (forgotBtn) {
        forgotBtn.addEventListener("click", (e) => {
            e.preventDefault()
            showForgot()
        })
    }

    const registerBtn = document.getElementById("registerBtn")
    if (registerBtn) {
        registerBtn.addEventListener("click", (e) => {
            e.preventDefault()
            showRegister()
        })
    }

    document.getElementById("backLoginBtn")?.addEventListener("click", showLogin)
    document.getElementById("registerBackBtn")?.addEventListener("click", showLogin)
    
    const forgotBackBtn = document.getElementById("forgotBackBtn")
    if (forgotBackBtn) {
        forgotBackBtn.addEventListener("click", showLogin)
    }
})


// ================= DRAG & DROP LINKS =================

let draggedItem = null;
let dragOverItem = null;

function makeLinksDraggable() {
    const linksTable = document.getElementById('links');
    if (!linksTable) return;
    
    const rows = linksTable.querySelectorAll('tr');
    
    rows.forEach((row, index) => {
        row.draggable = true;
        row.setAttribute('data-index', index);
        
        // إزالة أي event listeners قديمة
        row.removeEventListener('dragstart', handleDragStart);
        row.removeEventListener('dragenter', handleDragEnter);
        row.removeEventListener('dragleave', handleDragLeave);
        row.removeEventListener('dragover', handleDragOver);
        row.removeEventListener('dragend', handleDragEnd);
        row.removeEventListener('drop', handleDrop);
        
        // إضافة event listeners جديدة
        row.addEventListener('dragstart', handleDragStart);
        row.addEventListener('dragenter', handleDragEnter);
        row.addEventListener('dragleave', handleDragLeave);
        row.addEventListener('dragover', handleDragOver);
        row.addEventListener('dragend', handleDragEnd);
        row.addEventListener('drop', handleDrop);
    });
    
    // إضافة CSS
    const style = document.createElement('style');
    style.textContent = `
        .drag-handle {
            cursor: grab;
            user-select: none;
        }
        
        .drag-handle:active {
            cursor: grabbing;
        }
        
        .dragging {
            opacity: 0.5;
            background: #f0fdf4 !important;
        }
        
        .drag-over {
            border-top: 2px solid #4CAF50 !important;
            background: #f0fdf4;
        }
        
        .drag-over-bottom {
            border-bottom: 2px solid #4CAF50 !important;
        }
        
        tr[draggable="true"] {
            transition: transform 0.2s ease;
        }
    `;
    document.head.appendChild(style);
}

function handleDragStart(e) {
    draggedItem = this;
    this.classList.add('dragging');
    e.dataTransfer.effectAllowed = 'move';
    e.dataTransfer.setData('text/html', this.innerHTML);
}

function handleDragEnter(e) {
    e.preventDefault();
    if (this !== draggedItem) {
        dragOverItem = this;
        
        // تحديد مكان الإفلات (فوق أو تحت)
        const rect = this.getBoundingClientRect();
        const mouseY = e.clientY;
        const middleY = rect.top + rect.height / 2;
        
        if (mouseY < middleY) {
            this.classList.add('drag-over');
            this.classList.remove('drag-over-bottom');
        } else {
            this.classList.add('drag-over-bottom');
            this.classList.remove('drag-over');
        }
    }
}

function handleDragLeave(e) {
    this.classList.remove('drag-over');
    this.classList.remove('drag-over-bottom');
}

function handleDragOver(e) {
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
}

function handleDragEnd(e) {
    this.classList.remove('dragging');
    document.querySelectorAll('tr').forEach(row => {
        row.classList.remove('drag-over');
        row.classList.remove('drag-over-bottom');
    });
}

async function handleDrop(e) {
    e.preventDefault();
    this.classList.remove('drag-over');
    this.classList.remove('drag-over-bottom');
    
    if (draggedItem && dragOverItem && draggedItem !== dragOverItem) {
        const tbody = document.getElementById('links');
        const rows = Array.from(tbody.children);
        
        const draggedIndex = rows.indexOf(draggedItem);
        const targetIndex = rows.indexOf(dragOverItem);
        
        // تحديث الترتيب في DOM
        if (draggedIndex < targetIndex) {
            tbody.insertBefore(draggedItem, dragOverItem.nextSibling);
        } else {
            tbody.insertBefore(draggedItem, dragOverItem);
        }
        
        // ✅ حفظ الترتيب الجديد في السيرفر
        await saveLinkOrder();
    }
    
    draggedItem = null;
    dragOverItem = null;
}

async function saveLinkOrder() {
    const tbody = document.getElementById('links');
    const rows = tbody.querySelectorAll('tr');
    
    const order = [];
    rows.forEach((row, index) => {
        const linkId = row.getAttribute('data-link-id');
        if (linkId) {
            order.push({
                id: parseInt(linkId),
                order: index
            });
        }
    });

    async function saveOrder() {
    const rows = document.querySelectorAll("#links tr")
    const order = []

    rows.forEach(row => {
        order.push(row.dataset.id)
    })

    console.log("Saving order:", order)

    await api("/api/links/reorder", {
        method: "POST",
        body: JSON.stringify({ order })
    })
}
    
    //console.log("Saving order:", order); // للتصحيح
    
    try {
        const res = await api("/api/links/reorder", {
            method: "POST",
            body: JSON.stringify({ order })
        });
        
        if (res.ok) {
            toast("Links reordered successfully");
        } else {
            const error = await res.json();
            console.error("Reorder failed:", error);
            toast("Failed to save order");
        }
        
    } catch (e) {
        console.error("Reorder error:", e);
        toast("Failed to save order");
    }
}

// تحديث دالة loadLinks لإضافة data-link-id
async function loadLinks() {
    try {
        const res = await api("/api/admin/profile");
        const data = await res.json();

        const container = document.getElementById("links");
        container.innerHTML = "";

        // ✅ ترتيب الروابط حسب sort_order (الأهم!)
        const sortedLinks = data.links.sort((a, b) => {
            return (a.sort_order || 0) - (b.sort_order || 0);
        });

        sortedLinks.forEach(link => {
            const tr = document.createElement("tr");
            tr.setAttribute('data-link-id', link.id);
            tr.setAttribute('data-sort-order', link.sort_order || 0);
            
            // عمود السحب
            const tdDrag = document.createElement("td");
            tdDrag.className = 'drag-handle';
            tdDrag.innerHTML = '⋮⋮';
            tdDrag.style.cursor = 'grab';
            tdDrag.style.width = '30px';
            tdDrag.style.textAlign = 'center';
            tdDrag.style.fontSize = '18px';
            tdDrag.style.color = '#999';
            
            const tdName = document.createElement("td");
            tdName.textContent = link.name;
            
            const tdAction = document.createElement("td");
            const deleteBtn = document.createElement("button");
            deleteBtn.textContent = "Delete";
            deleteBtn.className = "delete";
            deleteBtn.addEventListener("click", () => deleteLink(link.id));
            
            tdAction.appendChild(deleteBtn);
            tr.appendChild(tdDrag);
            tr.appendChild(tdName);
            tr.appendChild(tdAction);
            
            container.appendChild(tr);
        });
        
        // ✅ تفعيل Drag & Drop بعد تحميل الروابط
        makeLinksDraggable();
        await updateLinkCounter();
        
    } catch (e) {
        console.error("Load links error", e);
        toast("Failed to load links");
    }
}


/* ================= HAMBURGER MENU ================= */

function createHamburgerMenu() {
    const mainElement = document.querySelector('.main')
    const hamburgerBtn = document.createElement('button')
    hamburgerBtn.className = 'menu-toggle'
    hamburgerBtn.id = 'menuToggle'
    hamburgerBtn.innerHTML = '☰'
    mainElement.insertBefore(hamburgerBtn, mainElement.firstChild)
    
    const overlay = document.createElement('div')
    overlay.className = 'overlay'
    overlay.id = 'overlay'
    document.body.appendChild(overlay)
    
    const sidebar = document.querySelector('.sidebar')
    if (window.innerWidth <= 768) {
        sidebar.classList.remove('active')
    }
}

function toggleMenu() {
    const sidebar = document.querySelector('.sidebar')
    const overlay = document.getElementById('overlay')
    const menuToggle = document.getElementById('menuToggle')
    
    sidebar.classList.toggle('active')
    overlay.classList.toggle('active')
    
    if (sidebar.classList.contains('active')) {
        menuToggle.innerHTML = '✕'
    } else {
        menuToggle.innerHTML = '☰'
    }
}

function closeMenu() {
    const sidebar = document.querySelector('.sidebar')
    const overlay = document.getElementById('overlay')
    const menuToggle = document.getElementById('menuToggle')
    
    sidebar.classList.remove('active')
    overlay.classList.remove('active')
    menuToggle.innerHTML = '☰'
}

function initHamburgerMenu() {
    createHamburgerMenu()
    
    document.getElementById('menuToggle')?.addEventListener('click', toggleMenu)
    document.getElementById('overlay')?.addEventListener('click', closeMenu)
    
    window.addEventListener('resize', () => {
        if (window.innerWidth > 768) {
            closeMenu()
        }
    })
    
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && window.innerWidth <= 768) {
            closeMenu()
        }
    })
}

// تهيئة قائمة الهامبرغر
if (document.querySelector('.main')) {
    initHamburgerMenu()
}