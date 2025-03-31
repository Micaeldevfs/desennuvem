from flask import Flask, jsonify, request, render_template, redirect, url_for
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    jwt_required,
    get_jwt_identity
)
from bson import ObjectId
from dotenv import load_dotenv
import os

# Carrega as variáveis de ambiente do arquivo .env
load_dotenv()

app = Flask(__name__)

app.config["MONGO_URI"] = os.getenv("MONGO_URI")
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")

mongo = PyMongo(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

#############################################
# Rotas para renderização de templates (Front-End)
#############################################

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register-page')
def register_page():
    return render_template('register.html')

@app.route('/login-page')
def login_page():
    return render_template('login.html')

@app.route('/products-page')
def products_page():
    return render_template('products.html')

@app.route('/cart-page')
@jwt_required(optional=True)
def view_cart_page():
    return render_template('cart.html')

@app.route('/profile-page')
@jwt_required(optional=True)
def profile_page():
    return render_template('profile.html')

# As páginas de administração são acessíveis apenas via perfil do admin
@app.route('/admin/bicycle-page')
@jwt_required(optional=True)
def admin_bicycle_page():
    return render_template("admin_bicycle.html")

@app.route('/admin/edit-user-page')
@jwt_required(optional=True)
def admin_edit_user_page():
    return render_template("admin_edit_user.html")

@app.route('/admin/edit-bicycle-page')
@jwt_required(optional=True)
def admin_edit_bicycle_page():
    return render_template("admin_edit_bicycle.html")

#############################################
# API Endpoints
#############################################

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    nome = data.get("nome")
    email = data.get("email")
    cpf = data.get("cpf")
    senha = data.get("senha")
    confirmacao_senha = data.get("confirmacao_senha")
    lgpd_consent = data.get("lgpd_consent", False)

    if not nome or not email or not cpf or not senha or not confirmacao_senha:
        return jsonify({"error": "Todos os campos (nome, email, CPF, senha e confirmação de senha) são obrigatórios."}), 400

    if senha != confirmacao_senha:
        return jsonify({"error": "As senhas não coincidem."}), 400

    if not lgpd_consent:
        return jsonify({"error": "Você deve aceitar o armazenamento dos seus dados conforme a LGPD."}), 400

    if mongo.db.users.find_one({"email": email}):
        return jsonify({"error": "Usuário já existe."}), 400

    hashed_password = bcrypt.generate_password_hash(senha).decode('utf-8')
    user = {
        "nome": nome,
        "email": email,
        "cpf": cpf,
        "password": hashed_password,
        "is_admin": False,
        "lgpd_consent": True
    }
    mongo.db.users.insert_one(user)
    return jsonify({"message": "Usuário cadastrado com sucesso."}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get("email")
    senha = data.get("senha")

    if not email or not senha:
        return jsonify({"error": "Email e senha são obrigatórios."}), 400

    user = mongo.db.users.find_one({"email": email})
    if user and bcrypt.check_password_hash(user["password"], senha):
        access_token = create_access_token(identity=str(user["_id"]))
        return jsonify({"access_token": access_token}), 200

    return jsonify({"error": "Email ou senha inválidos."}), 401

@app.route('/user/profile', methods=['GET'])
@jwt_required()
def user_profile():
    user_id = get_jwt_identity()
    user = mongo.db.users.find_one({"_id": ObjectId(user_id)})
    if not user:
        return jsonify({"error": "Usuário não encontrado."}), 404
    user_data = {
        "nome": user.get("nome"),
        "email": user.get("email"),
        "cpf": user.get("cpf"),
        "is_admin": user.get("is_admin", False),
        "lgpd_consent": user.get("lgpd_consent", False)
    }
    return jsonify({"user": user_data}), 200

@app.route('/admin/dashboard', methods=['GET'])
@jwt_required()
def admin_dashboard():
    user_id = get_jwt_identity()
    user = mongo.db.users.find_one({"_id": ObjectId(user_id)})
    if not user:
        return jsonify({"error": "Usuário não encontrado."}), 404
    if not user.get("is_admin", False):
        return jsonify({"error": "Acesso negado. Você não é administrador."}), 403
    return jsonify({"message": "Bem-vindo ao painel de administração!"}), 200

# Endpoint para listar todos os usuários (admin)
@app.route('/admin/users', methods=['GET'])
@jwt_required()
def get_all_users():
    admin_id = get_jwt_identity()
    admin = mongo.db.users.find_one({"_id": ObjectId(admin_id)})
    if not admin or not admin.get("is_admin", False):
        return jsonify({"error": "Acesso negado."}), 403
    users = list(mongo.db.users.find())
    for u in users:
        u['_id'] = str(u['_id'])
        if 'password' in u:
            del u['password']
    return jsonify({"users": users}), 200

# Endpoint para obter um usuário específico (admin)
@app.route('/admin/user/<string:user_id>', methods=['GET'])
@jwt_required()
def get_user(user_id):
    admin_id = get_jwt_identity()
    admin = mongo.db.users.find_one({"_id": ObjectId(admin_id)})
    if not admin or not admin.get("is_admin", False):
        return jsonify({"error": "Acesso negado."}), 403
    user = mongo.db.users.find_one({"_id": ObjectId(user_id)})
    if not user:
        return jsonify({"error": "Usuário não encontrado."}), 404
    user['_id'] = str(user['_id'])
    if 'password' in user:
        del user['password']
    return jsonify({"user": user}), 200

# Endpoint para editar usuários (admin)
@app.route('/admin/edit-user/<string:user_id>', methods=['PATCH'])
@jwt_required()
def edit_user(user_id):
    admin_id = get_jwt_identity()
    admin = mongo.db.users.find_one({"_id": ObjectId(admin_id)})
    if not admin or not admin.get("is_admin", False):
        return jsonify({"error": "Acesso negado. Somente administradores podem editar usuários."}), 403
    data = request.get_json()
    update_data = {}
    if data.get("nome"):
        update_data["nome"] = data.get("nome")
    if data.get("email"):
        update_data["email"] = data.get("email")
    if data.get("cpf"):
        update_data["cpf"] = data.get("cpf")
    if data.get("is_admin") is not None:
        update_data["is_admin"] = data.get("is_admin")
    if data.get("nova_senha"):
        new_hashed_password = bcrypt.generate_password_hash(data.get("nova_senha")).decode('utf-8')
        update_data["password"] = new_hashed_password
    if not update_data:
        return jsonify({"error": "Nenhum dado para atualizar."}), 400
    result = mongo.db.users.update_one({"_id": ObjectId(user_id)}, {"$set": update_data})
    if result.modified_count == 0:
        return jsonify({"message": "Nenhuma alteração realizada ou usuário não encontrado."}), 404
    return jsonify({"message": "Usuário atualizado com sucesso."}), 200

# Endpoint para listar produtos e bicicletas (loja)
@app.route('/products', methods=['GET'])
def list_products():
    products = list(mongo.db.products.find())
    bicycles = list(mongo.db.bicycles.find())
    
    # Para produtos normais
    for p in products:
        p['_id'] = str(p['_id'])
        p['type'] = 'product'
    
    # Para bicicletas, converte os campos para os mesmos nomes dos produtos se desejar
    for b in bicycles:
        b['_id'] = str(b['_id'])
        b['type'] = 'bicycle'
        b['name'] = b.get("marca", "") + " " + b.get("modelo", "")
        b['description'] = b.get("descricao", "")
        b['price'] = b.get("preco", "")
    
    all_items = products + bicycles
    return jsonify({"products": all_items}), 200

@app.route('/products/<string:product_id>', methods=['GET'])
def product_details(product_id):
    try:
        product = mongo.db.products.find_one({"_id": ObjectId(product_id)})
    except Exception as e:
        return jsonify({"error": "ID inválido."}), 400
    if not product:
        return jsonify({"error": "Produto não encontrado."}), 404
    product['_id'] = str(product['_id'])
    return jsonify({"product": product}), 200

@app.route('/products/add', methods=['POST'])
@jwt_required()
def add_product():
    user_id = get_jwt_identity()
    user = mongo.db.users.find_one({"_id": ObjectId(user_id)})
    if not user or not user.get("is_admin", False):
        return jsonify({"error": "Acesso negado."}), 403
    data = request.get_json()
    name = data.get("name")
    price = data.get("price")
    description = data.get("description", "")
    if not (name and price):
        return jsonify({"error": "Nome e preço são obrigatórios."}), 400
    product = {"name": name, "price": price, "description": description}
    mongo.db.products.insert_one(product)
    return jsonify({"message": "Produto adicionado com sucesso."}), 201

# Endpoints para bicicletas
@app.route('/bicycles/add', methods=['POST'])
@jwt_required()
def add_bicycle():
    admin_id = get_jwt_identity()
    admin = mongo.db.users.find_one({"_id": ObjectId(admin_id)})
    if not admin or not admin.get("is_admin", False):
        return jsonify({"error": "Acesso negado."}), 403
    data = request.get_json()
    required_fields = ["marca", "modelo", "cor", "preco"]
    for field in required_fields:
        if not data.get(field):
            return jsonify({"error": f"{field} é obrigatório."}), 400
    bicycle = {
        "marca": data.get("marca"),
        "modelo": data.get("modelo"),
        "cor": data.get("cor"),
        "preco": data.get("preco"),
        "descricao": data.get("descricao", "")
    }
    mongo.db.bicycles.insert_one(bicycle)
    return jsonify({"message": "Bicicleta cadastrada com sucesso."}), 201

@app.route('/admin/bicycles', methods=['GET'])
@jwt_required()
def get_all_bicycles():
    admin_id = get_jwt_identity()
    admin = mongo.db.users.find_one({"_id": ObjectId(admin_id)})
    if not admin or not admin.get("is_admin", False):
        return jsonify({"error": "Acesso negado."}), 403
    bicycles = list(mongo.db.bicycles.find())
    for b in bicycles:
        b['_id'] = str(b['_id'])
    return jsonify({"bicycles": bicycles}), 200

@app.route('/admin/bicycles/<string:bicycle_id>', methods=['GET'])
@jwt_required()
def get_bicycle(bicycle_id):
    admin_id = get_jwt_identity()
    admin = mongo.db.users.find_one({"_id": ObjectId(admin_id)})
    if not admin or not admin.get("is_admin", False):
        return jsonify({"error": "Acesso negado."}), 403
    try:
        bicycle = mongo.db.bicycles.find_one({"_id": ObjectId(bicycle_id)})
    except Exception as e:
        return jsonify({"error": "ID inválido."}), 400
    if not bicycle:
        return jsonify({"error": "Bicicleta não encontrada."}), 404
    bicycle['_id'] = str(bicycle['_id'])
    return jsonify({"bicycle": bicycle}), 200

@app.route('/admin/edit-bicycle/<string:bicycle_id>', methods=['PATCH'])
@jwt_required()
def edit_bicycle(bicycle_id):
    admin_id = get_jwt_identity()
    admin = mongo.db.users.find_one({"_id": ObjectId(admin_id)})
    if not admin or not admin.get("is_admin", False):
        return jsonify({"error": "Acesso negado."}), 403
    data = request.get_json()
    update_data = {}
    if data.get("marca"):
        update_data["marca"] = data.get("marca")
    if data.get("modelo"):
        update_data["modelo"] = data.get("modelo")
    if data.get("cor"):
        update_data["cor"] = data.get("cor")
    if data.get("preco"):
        update_data["preco"] = data.get("preco")
    if data.get("descricao") is not None:
        update_data["descricao"] = data.get("descricao")
    if not update_data:
        return jsonify({"error": "Nenhum dado para atualizar."}), 400
    result = mongo.db.bicycles.update_one({"_id": ObjectId(bicycle_id)}, {"$set": update_data})
    if result.modified_count == 0:
        return jsonify({"message": "Nenhuma alteração realizada ou bicicleta não encontrada."}), 404
    return jsonify({"message": "Bicicleta atualizada com sucesso."}), 200

# Endpoints para o carrinho
@app.route('/cart/add', methods=['POST'])
@jwt_required()
def add_to_cart():
    user_id = get_jwt_identity()
    data = request.get_json()
    product_id = data.get("product_id")
    quantity = data.get("quantity", 1)

    if not product_id:
        return jsonify({"error": "ID do produto é necessário."}), 400

    try:
        # Tenta buscar o item na coleção 'products'
        product = mongo.db.products.find_one({"_id": ObjectId(product_id)})
        # Se não encontrar, tenta na coleção 'bicycles'
        if not product:
            product = mongo.db.bicycles.find_one({"_id": ObjectId(product_id)})
    except Exception as e:
        return jsonify({"error": "ID do produto inválido."}), 400

    if not product:
        return jsonify({"error": "Produto não encontrado."}), 404

    cart = mongo.db.carts.find_one({"user_id": user_id})
    if not cart:
        cart = {"user_id": user_id, "items": []}
        mongo.db.carts.insert_one(cart)
        cart = mongo.db.carts.find_one({"user_id": user_id})

    item_index = None
    for index, item in enumerate(cart.get("items", [])):
        if item["product_id"] == product_id:
            item_index = index
            break

    if item_index is not None:
        cart["items"][item_index]["quantity"] += quantity
        mongo.db.carts.update_one({"user_id": user_id}, {"$set": {"items": cart["items"]}})
    else:
        mongo.db.carts.update_one({"user_id": user_id}, {"$push": {"items": {"product_id": product_id, "quantity": quantity}}})

    return jsonify({"message": "Produto adicionado ao carrinho."}), 200


@app.route('/cart', methods=['GET'])
@jwt_required()
def view_cart():
    user_id = get_jwt_identity()
    cart = mongo.db.carts.find_one({"user_id": user_id})
    if not cart or not cart.get("items"):
        return jsonify({"cart": []}), 200

    detailed_items = []
    for item in cart.get("items", []):
        try:
            product = mongo.db.products.find_one({"_id": ObjectId(item["product_id"])})
            if not product:
                product = mongo.db.bicycles.find_one({"_id": ObjectId(item["product_id"])})
        except Exception as e:
            continue
        if product:
            product['_id'] = str(product['_id'])
            if 'marca' in product:
                product['name'] = product.get("marca", "") + " " + product.get("modelo", "")
                product['description'] = product.get("descricao", "")
                product['price'] = product.get("preco", "")
                product['type'] = 'bicycle'
            else:
                product['type'] = 'product'
            detailed_items.append({
                "product": product,
                "quantity": item["quantity"]
            })
    return jsonify({"cart": detailed_items}), 200

@app.route('/cart/remove', methods=['POST'])
@jwt_required()
def remove_from_cart():
    user_id = get_jwt_identity()
    data = request.get_json()
    product_id = data.get("product_id")
    if not product_id:
        return jsonify({"error": "ID do produto é necessário."}), 400
    mongo.db.carts.update_one({"user_id": user_id}, {"$pull": {"items": {"product_id": product_id}}})
    return jsonify({"message": "Produto removido do carrinho."}), 200

@app.route('/cart/checkout', methods=['POST'])
@jwt_required()
def checkout():
    user_id = get_jwt_identity()
    mongo.db.carts.delete_one({"user_id": user_id})
    return jsonify({"message": "Compra finalizada e carrinho limpo."}), 200

if __name__ == '__main__':
    app.run(debug=True, port=5000)
