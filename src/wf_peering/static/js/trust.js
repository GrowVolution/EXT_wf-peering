(function (global) {
    "use strict"

    function clamp(score) {
        const value = Math.round(Number(score))
        if (!Number.isFinite(value)) return null
        return Math.max(0, Math.min(100, value))
    }

    function hue(score) {
        const value = clamp(score)
        return value === null ? null : Math.round(value * 1.2)
    }

    function color(score) {
        const h = hue(score)
        if (h === null) return null
        return {
            hue: h,
            accent: `hsl(${h}, 75%, 26%)`,
            border: `hsl(${h}, 75%, 32%)`,
            surface: `hsl(${h}, 80%, 95%)`,
            text: `hsl(${h}, 90%, 20%)`,
            accent_dark: `hsl(${h}, 75%, 65%)`,
            surface_dark: `hsl(${h}, 45%, 13%)`,
            text_dark: `hsl(${h}, 85%, 78%)`
        }
    }

    function apply(element, score) {
        const palette = color(score)
        if (!element) return
        if (!palette) {
            element.removeAttribute("data-trust")
            element.style.removeProperty("--trust-h")
            return
        }
        element.setAttribute("data-trust", "")
        element.style.setProperty("--trust-h", String(palette.hue))
    }

    global.wfTrust = { clamp, hue, color, apply }
})(window)
