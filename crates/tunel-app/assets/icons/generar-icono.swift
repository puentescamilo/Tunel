// Genera el icono de Túnel: cuadrado redondeado con degradado verde y el símbolo ">_".
//
// Uso: swift generar-icono.swift <salida.png> [margen]
// El margen por omisión (100 de 1024) es el de macOS, que no recorta el icono y espera
// aire alrededor. Windows y Linux lo muestran tal cual: ahí se usa un margen mínimo para
// que no se vea más pequeño que los demás (ver generar-iconos.sh).
import AppKit

let size: CGFloat = 1024
let out = CommandLine.arguments[1]
let inset: CGFloat = CommandLine.arguments.count > 2 ? CGFloat(Double(CommandLine.arguments[2])!) : 100
// Lienzo de 1024 píxeles exactos, que no depende de si la pantalla es Retina. El perfil de
// color es el de icon-1024.png, el icono original: así los colores salen iguales que en él
// (Windows no aplica el perfil y muestra los valores tal cual).
let reference = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
    .appendingPathComponent("icon-1024.png")
let space = CGImageSourceCreateWithURL(reference as CFURL, nil)
    .flatMap { CGImageSourceCreateImageAtIndex($0, 0, nil) }?.colorSpace
    ?? CGColorSpace(name: CGColorSpace.sRGB)!
let ctx = CGContext(
    data: nil, width: Int(size), height: Int(size), bitsPerComponent: 8, bytesPerRow: 0,
    space: space,
    bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
NSGraphicsContext.current = NSGraphicsContext(cgContext: ctx, flipped: false)

let rect = CGRect(x: inset, y: inset, width: size - 2 * inset, height: size - 2 * inset)
let radius = rect.width * 0.225
// Las medidas de dentro se dieron para el icono de macOS (824 de ancho): crecen con él.
let scale = rect.width / 824
let path = CGPath(roundedRect: rect, cornerWidth: radius, cornerHeight: radius, transform: nil)

ctx.saveGState()
// La sombra necesita el margen para caber; sin él, se cortaría en el borde.
if inset >= 60 {
    ctx.setShadow(offset: CGSize(width: 0, height: -12), blur: 30, color: NSColor(white: 0, alpha: 0.35).cgColor)
}
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
let screen = rect.insetBy(dx: 120 * scale, dy: 150 * scale)
let screenPath = CGPath(roundedRect: screen, cornerWidth: 56 * scale, cornerHeight: 56 * scale, transform: nil)
ctx.addPath(screenPath)
ctx.setFillColor(NSColor(red: 0.06, green: 0.07, blue: 0.09, alpha: 0.92).cgColor)
ctx.fillPath()
ctx.restoreGState()

let font = NSFont.monospacedSystemFont(ofSize: 250 * scale, weight: .bold)
let text = NSAttributedString(string: ">_", attributes: [
    .font: font,
    .foregroundColor: NSColor(red: 0.36, green: 0.9, blue: 0.74, alpha: 1),
])
let textSize = text.size()
text.draw(at: CGPoint(x: screen.midX - textSize.width / 2, y: screen.midY - textSize.height / 2 + 10 * scale))

let rep = NSBitmapImageRep(cgImage: ctx.makeImage()!)
try! rep.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: out))
