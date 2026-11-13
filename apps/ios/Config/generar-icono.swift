// Genera el icono de Túnel para iOS y iPadOS: el mismo dibujo que el del escritorio
// (crates/tunel-app/assets/icons/generar-icono.swift), pero a sangre, opaco y sin esquinas
// redondeadas, porque iOS recorta el icono él mismo.
//
//   swift apps/ios/Config/generar-icono.swift apps/ios/Tunel/Assets.xcassets/AppIcon.appiconset/AppIcon.png
import AppKit

let size = 1024
let out = CommandLine.arguments[1]
// Los colores, en sRGB, son los que quedaron en el PNG del escritorio (que se dibujó con el
// perfil de la pantalla y por eso no coinciden con los números de su script).
let space = CGColorSpace(name: CGColorSpace.sRGB)!
func color(_ r: CGFloat, _ g: CGFloat, _ b: CGFloat, _ a: CGFloat = 1) -> CGColor {
    CGColor(colorSpace: space, components: [r, g, b, a])!
}
let ctx = CGContext(
    data: nil, width: size, height: size, bitsPerComponent: 8, bytesPerRow: 0, space: space,
    bitmapInfo: CGImageAlphaInfo.noneSkipLast.rawValue)!
let rect = CGRect(x: 0, y: 0, width: size, height: size)

let colors = [color(0.0, 0.875, 0.74), color(0.0, 0.57, 0.50)] as CFArray
let gradient = CGGradient(colorsSpace: space, colors: colors, locations: [0, 1])!
ctx.drawLinearGradient(gradient, start: CGPoint(x: rect.minX, y: rect.maxY), end: CGPoint(x: rect.maxX, y: rect.minY), options: [])

// Ventana de terminal oscura, en la misma proporción que en el escritorio.
let screen = rect.insetBy(dx: 150, dy: 186)
ctx.addPath(CGPath(roundedRect: screen, cornerWidth: 70, cornerHeight: 70, transform: nil))
ctx.setFillColor(color(0.06, 0.07, 0.09, 0.92))
ctx.fillPath()

NSGraphicsContext.current = NSGraphicsContext(cgContext: ctx, flipped: false)
let font = NSFont.monospacedSystemFont(ofSize: 310, weight: .bold)
let text = NSAttributedString(string: ">_", attributes: [
    .font: font,
    .foregroundColor: NSColor(cgColor: color(0.21, 0.9, 0.76))!,
])
let textSize = text.size()
text.draw(at: CGPoint(x: screen.midX - textSize.width / 2, y: screen.midY - textSize.height / 2 + 12))

let rep = NSBitmapImageRep(cgImage: ctx.makeImage()!)
try! rep.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: out))
