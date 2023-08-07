# from flask import Flask, request, redirect, url_for, render_template
# from werkzeug.utils import secure_filename
# from androguard.misc import AnalyzeAPK

# import os

# UPLOAD_FOLDER = 'uploads'
# ALLOWED_EXTENSIONS = {'apk'}

# app = Flask(__name__, template_folder='web_templates')
# app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
# app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100 MB max file size

# def allowed_file(filename):
#     return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# @app.route('/', methods=['GET', 'POST'])
# def upload_file():
#     if request.method == 'POST':
#         file = request.files['file']
#         if file and allowed_file(file.filename):
#             filename = secure_filename(file.filename)
#             file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
#             file.save(file_path)
#             return redirect(url_for('analyze_apk', filename=filename))
#         else:
#             return "Invalid file type. Please upload an APK file."

#     return '''
#     <!doctype html>
#     <title>Upload APK File</title>
#     <h1>Upload APK File</h1>
#     <form method=post enctype=multipart/form-data>
#       <input type=file name=file>
#       <input type=submit value=Upload>
#     </form>
#     '''

# @app.route('/analysis/<filename>')
# def analyze_apk(filename):
#     file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
#     #a, d, dx = AnalyzeAPK(file_path)

#     analysis = {
#         'app_name': "AAAA",
#         'package': "BBBB",
#     }

#     return render_template('analysis.html', analysis=analysis)

# if __name__ == '__main__':
#     if not os.path.exists(UPLOAD_FOLDER):
#         os.makedirs(UPLOAD_FOLDER)
#     app.run(debug=True)
import os
import time
from flask import Flask, render_template, request, redirect, url_for
from werkzeug.utils import secure_filename
from analyze import backend_analysis

UPLOAD_FOLDER = 'web_static/uploads'
ALLOWED_EXTENSIONS = {'apk'}
CURRENT_DIRECTORY = os.path.dirname(os.path.realpath(__file__))


app = Flask(__name__, template_folder='web_templates', static_folder='web_static')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.use_static_for = True

# Helper function to check if the file extension is allowed
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Route for the main page with the file upload form
@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # Check if a file is selected
        if 'file' not in request.files:
            return redirect(request.url)

        file = request.files['file']

        # Check if the file is empty
        if file.filename == '':
            return redirect(request.url)
        # Check if the file is allowed
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

            # Save the file
            file.save(file_path)
            apk_dir = os.path.join(CURRENT_DIRECTORY, UPLOAD_FOLDER)
            print(apk_dir)
            print(filename)
            # print(request.form['tpl'])
            # print(request.form['icc'])

            backend_analysis(filename, apk_dir, request.form['tpl'], request.form['icc'])
            # Redirect to the analysis page
            return redirect(url_for('analyze_file', filename=filename, tpl=request.form['tpl'], icc=request.form['icc'] ))

    return render_template('upload.html')

# Route for the analysis page with the progress bar
@app.route('/<filename>-<tpl>-<icc>')
def analyze_file(filename, tpl, icc):
    # Simulating the analysis process
    time.sleep(1)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    # Get the analysis result
    #pdf_path = os.path.join(UPLOAD_FOLDER, filename + '.gv.pdf')
    svg_path = os.path.join(UPLOAD_FOLDER, filename + '.gv.svg')
    print(svg_path)

    return render_template('analysis.html', svg_path=svg_path)

if __name__ == '__main__':
    app.run(debug=True)
