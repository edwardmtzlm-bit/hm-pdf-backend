from fastapi import FastAPI, UploadFile, File, Form
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware

from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch

from PyPDF2 import PdfReader, PdfWriter

from typing import Optional
import io
import textwrap

app = FastAPI(
    title="HM PDF Backend",
    description=(
        "Backend simple para generar y proteger PDFs.\n"
        "- /generar-pdf: genera un PDF a partir de título y cuerpo.\n"
        "- /proteger-pdf: recibe un PDF y devuelve versión protegida."
    ),
)

# CORS básico por si lo llamas desde tu web
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # luego lo puedes restringir a tu dominio
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =========================
#   UTILIDAD: CREAR PDF
# =========================
def crear_pdf_en_memoria(titulo: str, cuerpo: str) -> bytes:
    """
    Genera un PDF simple (tamaño carta, márgenes decentes, respeta saltos de línea).
    Devuelve los bytes del PDF.
    """
    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter

    # Márgenes
    margen_x = 1 * inch
    margen_superior = height - 1 * inch
    margen_inferior = 1 * inch

    # Config fuentes
    font_title = ("Helvetica-Bold", 16)
    font_body = ("Helvetica", 11)
    leading = 14  # interlineado

    # ===== Página inicial =====
    c.setTitle(titulo or "Documento")

    # TÍTULO
    y = margen_superior
    if titulo:
        c.setFont(*font_title)
        wrapper_title = textwrap.TextWrapper(width=80, break_long_words=False)
        for line in wrapper_title.wrap(titulo):
            c.drawString(margen_x, y, line)
            y -= leading + 2
        y -= 10  # espacio extra después del título

    # CUERPO
    c.setFont(*font_body)
    wrapper = textwrap.TextWrapper(width=95, break_long_words=False)

    def nueva_pagina():
        nonlocal y
        c.showPage()
        y = height - 1 * inch
        c.setFont(*font_body)

    for raw_parrafo in cuerpo.split("\n"):
        parrafo = raw_parrafo.rstrip()

        # Línea en blanco -> salto de párrafo
        if parrafo.strip() == "":
            y -= leading
            if y < margen_inferior:
                nueva_pagina()
            continue

        # Romper en líneas
        for line in wrapper.wrap(parrafo):
            if y < margen_inferior:
                nueva_pagina()
            c.drawString(margen_x, y, line)
            y -= leading

    c.showPage()
    c.save()
    buffer.seek(0)
    return buffer.read()


# =========================
#       ENDPOINTS
# =========================
@app.get("/ping")
def ping():
    return {"ok": True}


@app.post("/generar-pdf")
async def generar_pdf(
    titulo: str = Form(..., description="Título del documento"),
    cuerpo: str = Form(..., description="Cuerpo del documento"),
    proteger: bool = Form(False, description="Si es True, bloquea impresión y copia"),
    plantilla: Optional[UploadFile] = File(
        None,
        description="Plantilla PDF (por ahora se recibe pero NO se mezcla aún)",
    ),
):
    """
    - Crea un PDF desde título/cuerpo.
    - (Por ahora) ignora la plantilla.
    - Si 'proteger' es True, aplica restricciones.
    """
    try:
        # 1) Generar PDF base
        pdf_bytes = crear_pdf_en_memoria(titulo, cuerpo)

        # 2) Plantilla por ahora ignorada (para que no marque sin usar)
        _ = plantilla

        # 3) Aplicar protección (opcional)
        if proteger:
            reader = PdfReader(io.BytesIO(pdf_bytes))
            writer = PdfWriter()
            for page in reader.pages:
                writer.add_page(page)

            # 0b0000 -> todos los permisos desactivados (incluye imprimir/copiar)
            permissions_flag = 0b0000

            writer.encrypt(
                "",
                "HM2025!",       # contraseña de propietario
                permissions_flag=permissions_flag,
            )

            out_buf = io.BytesIO()
            writer.write(out_buf)
            out_buf.seek(0)
            pdf_bytes = out_buf.read()

        # 4) Respuesta como archivo descargable
        filename = (titulo or "documento").strip() or "documento"
        filename = filename.replace("/", "_").replace("\\", "_")[:60] + ".pdf"

        return StreamingResponse(
            io.BytesIO(pdf_bytes),
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"'
            },
        )

    except Exception as e:
        msg = f"Internal Server Error: {type(e).__name__}: {e}"
        return StreamingResponse(
            io.BytesIO(msg.encode("utf-8")),
            media_type="text/plain",
            status_code=500,
        )


@app.post("/proteger-pdf")
async def proteger_pdf(
    archivo: UploadFile = File(..., description="PDF ya generado que quieres proteger"),
):
    """
    - Recibe un PDF (por ejemplo, el que generas en React con tu plantilla).
    - Le aplica cifrado y bloquea impresión/copia.
    - Devuelve el PDF protegido.
    """
    try:
        data = await archivo.read()

        reader = PdfReader(io.BytesIO(data))
        writer = PdfWriter()
        for page in reader.pages:
            writer.add_page(page)

        # Sin permisos: no imprimir, no copiar, etc.
        permissions_flag = 0b0000

        writer.encrypt(
            "",
            "HM2025!",           # contraseña de propietario
            permissions_flag=permissions_flag,
        )

        out_buf = io.BytesIO()
        writer.write(out_buf)
        out_buf.seek(0)

        filename = archivo.filename or "documento_protegido.pdf"
        if not filename.lower().endswith(".pdf"):
            filename += ".pdf"

        return StreamingResponse(
            out_buf,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"'
            },
        )

    except Exception as e:
        msg = f"Internal Server Error: {type(e).__name__}: {e}"
        return StreamingResponse(
            io.BytesIO(msg.encode("utf-8")),
            media_type="text/plain",
            status_code=500,
        )
