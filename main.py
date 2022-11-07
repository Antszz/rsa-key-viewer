import os

from Crypto.PublicKey import RSA
from flask import flash
from flask import Flask
from flask import redirect
from flask import render_template
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from flask_wtf.file import FileField
from flask_wtf.file import FileAllowed
from flask_wtf.file import FileRequired
from wtforms import SubmitField

app = Flask(__name__)
app.config['WTF_CSRF_ENABLED']= False
app.config['SECRET_KEY']='KEY_SECRET'
bootstrap = Bootstrap(app)


class FileForm(FlaskForm):
    file = FileField(validators=[
        FileRequired(),
        FileAllowed(['pem'], "Solo archivos .pem")
    ])
    verify = SubmitField('Upload')


def read_pem_file():
    pem_data = None
    try:
        pem_file = open('key.pem')
        pem_data = pem_file.read()
        pem_file.close()
        os.remove('key.pem')
    except FileNotFoundError:
        pass
    return pem_data


@app.route('/', methods=['GET', 'POST'])
def index():
    form = FileForm()
    if form.validate_on_submit():
        f = form.file.data
        filename = 'key.pem'
        f.save(os.path.join(
            os.path.abspath(os.path.dirname(__file__)), filename
        ))
        return redirect('/')

    pem_data = read_pem_file()
    key_data = {}
    if pem_data:
        try:
            rsa = RSA.importKey(pem_data)
        except Exception:
            flash("No es una llave PEM valida")
            return redirect('/')
        if 'PRIVATE' in pem_data:
            key_data.update({
                'keyType': 'private',
                'modulus': rsa.n,
                'publicExponent': rsa.e,
                'privateExponent': rsa.d,
                'prime1': rsa.p,
                'prime2': rsa.q,
                'exponent1': rsa._dp,
                'exponent2': rsa._dq,
                'coefficient': rsa.u,
            })
        elif 'PUBLIC' in pem_data:
            key_data.update({
                'keyType': 'public',
                'modulus': rsa.n,
                'publicExponent': rsa.e,
            })
        else:
            flash("No es una llave PEM valida")
            return redirect('/')

    return render_template('index.html', form=form, key_data=key_data)

if __name__=='__main__':
    app.config['ENV']='development'
    app.run(debug=True)
