// Genera el icono de Túnel: cuadrado redondeado con degradado verde y el símbolo ">_".
import AppKit

let size: CGFloat = 1024
let out = CommandLine.arguments[1]
let image = NSImage(size: NSSize(width: size, height: size))
image.lockFocus()
let ctx = NSGraphicsContext.current!.cgContext

// Margen estilo macOS (el sistema no recorta el icono).
let inset: CGFloat = 100
let rect = CGRect(x: inset, y: inset, width: size - 2 * inset, height: size - 2 * inset)
let radius = rect.width * 0.225
let path = CGPath(roundedRect: rect, cornerWidth: radius, cornerHeight: radius, transform: nil)

ctx.saveGState()
ctx.setShadow(offset: CGSize(width: 0, height: -12), blur: 30, color: NSColor(white: 0, alpha: 0.35).cgColor)
ctx.addPath(path)
ctx.setFillColor(NSColor(red: 0.06, green: 0.07, blue: 0.09, alpha: 1).cgColor)
ctx.fillPath()
ctx.restoreGState()

ctx.saveGState()
ctx.addPath(path)
ctx.clip()
let colors = [NSColor(red: 0.28, green: 0.88, blue: 0.72, alpha: 1).cgColor,
              NSColor(red: 0.05, green: 0.55, blue: 0.47, alpha: 1).cgColor] as CFArray
let gradient = CGGradient(colorsSpace: CGColorSpaceCreateDeviceRGB(), colors: colors, locations: [0, 1])!
ctx.drawLinearGradient(gradient, start: CGPoint(x: rect.minX, y: rect.maxY), end: CGPoint(x: rect.maxX, y: rect.minY), options: [])
// Ventana de terminal oscura dentro del icono.
let screen = rect.insetBy(dx: 120, dy: 150)
let screenPath = CGPath(roundedRect: screen, cornerWidth: 56, cornerHeight: 56, transform: nil)
ctx.addPath(screenPath)
ctx.setFillColor(NSColor(red: 0.06, green: 0.07, blue: 0.09, alpha: 0.92).cgColor)
ctx.fillPath()
ctx.restoreGState()

let font = NSFont.monospacedSystemFont(ofSize: 250, weight: .bold)
let text = NSAttributedString(string: ">_", attributes: [
    .font: font,
    .foregroundColor: NSColor(red: 0.36, green: 0.9, blue: 0.74, alpha: 1),
])
let textSize = text.size()
text.draw(at: CGPoint(x: screen.midX - textSize.width / 2, y: screen.midY - textSize.height / 2 + 10))
image.unlockFocus()

let rep = NSBitmapImageRep(data: image.tiffRepresentation!)!
try! rep.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: out))
