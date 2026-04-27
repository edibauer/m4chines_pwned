from flask import Flask, request, render_template_string
from lxml import etree

app = Flask(__name__)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>Laboratorio XSLT Injection</title></head>
<body>
    <h1>Transformador XML a HTML</h1>
    <form method="post" enctype="multipart/form-data">
        <label>Archivo XML:</label><br>
        <textarea name="xml_data" rows="10" cols="50"></textarea><br><br>
        <label>Hoja de Estilo XSLT:</label><br>
        <textarea name="xsl_data" rows="10" cols="50"></textarea><br><br>
        <input type="submit" value="Transformar">
    </form>
    {% if result %}<h2>Resultado:</h2><pre>{{ result }}</pre>{% endif %}
    {% if error %}<h2 style="color:red">Error:</h2><pre>{{ error }}</pre>{% endif %}
</body>
</html>
"""

# 🔓 Resolver personalizado que convierte texto plano a XML
class AllowFileResolver(etree.Resolver):
    def resolve(self, system_url, public_id, context):
        if system_url.startswith('file://'):
            filepath = system_url[7:]  # Quitar 'file://'
            try:
                with open(filepath, 'r') as f:
                    content = f.read()
                # Envolver el contenido en etiquetas XML válidas
                xml_content = f"<?xml version='1.0'?><file><![CDATA[{content}]]></file>"
                return self.resolve_string(xml_content, context)
            except Exception as e:
                return None
        return None

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    error = None

    if request.method == 'POST':
        xml_input = request.form.get('xml_data')
        xsl_input = request.form.get('xsl_data')

        if xml_input and xsl_input:
            try:
                parser = etree.XMLParser()
                parser.resolvers.add(AllowFileResolver())
                
                xml_doc = etree.fromstring(xml_input.encode('utf-8'), parser)
                xsl_doc = etree.fromstring(xsl_input.encode('utf-8'), parser)
                
                transform = etree.XSLT(xsl_doc)
                result_doc = transform(xml_doc)
                result = str(result_doc)

            except Exception as e:
                error = f"Error: {type(e).__name__}: {e}"

    return render_template_string(HTML_TEMPLATE, result=result, error=error)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)