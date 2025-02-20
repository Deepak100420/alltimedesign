from flask import Flask, request, jsonify
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from pymongo import MongoClient
from bson import ObjectId
from datetime import timedelta 
from config.credientials import users_collection,templates_collection,KEY
import os

app = Flask(__name__)
bcrypt = Bcrypt(app)

# Secret Key for JWT
app.config['JWT_SECRET_KEY'] = KEY
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=30) 

jwt = JWTManager(app)

# -------------------- REGISTER ENDPOINT --------------------
@app.route("/register", methods=["POST"])
def register():
    try:
        data = request.get_json()
        first_name = data.get("first_name")
        last_name = data.get("last_name")
        email = data.get("email")
        password = data.get("password")

        missing_fields = []
        if not first_name: missing_fields.append("first_name")
        if not last_name: missing_fields.append("last_name")
        if not email: missing_fields.append("email")
        if not password: missing_fields.append("password")

        if missing_fields:
            return jsonify({"message": "Missing required fields", "missing": missing_fields}), 400

        if users_collection.find_one({"email": email}):
            return jsonify({"message": "Email already registered"}), 400

        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
        users_collection.insert_one({
            "first_name": first_name,
            "last_name": last_name,
            "email": email,
            "password": hashed_password,
        })

        return jsonify({"message": "User registered successfully"}), 201

    except Exception as e:
        return jsonify({"message": "An error occurred", "error": str(e)}), 500

# -------------------- LOGIN ENDPOINT --------------------
@app.route("/login", methods=["POST"])
def login():
    try:
        data = request.get_json()
        email = data.get("email")
        password = data.get("password")

        user = users_collection.find_one({"email": email})
        if not user or not user.get("password") or not bcrypt.check_password_hash(user["password"], password):
            return jsonify({"message": "Invalid email or password"}), 401

        access_token = create_access_token(identity=user["email"])  # ✅ Ensure email is used in JWT
        return jsonify({"access_token": access_token}), 200

    except Exception as e:
        print("Error:", e)
        return jsonify({"message": "Internal Server Error"}), 500

# -------------------- CREATE TEMPLATE --------------------
@app.route("/template", methods=["POST"])
@jwt_required()
def create_template():
    try:
        user_email = get_jwt_identity()
        data = request.get_json()

        required_fields = ["template_name", "subject", "body"]
        missing_fields = [field for field in required_fields if field not in data]
        if missing_fields:
            return jsonify({"error": "Missing required fields", "missing": missing_fields}), 400

        template = {
            "user_email": user_email,
            "template_name": data["template_name"],
            "subject": data["subject"],
            "body": data["body"]
        }
        inserted = templates_collection.insert_one(template)
        return jsonify({"message": "Template created", "template_id": str(inserted.inserted_id)}), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
    
    
#----------------------Retrieve All Templates for Logged-in User----------------------------
@app.route("/template", methods=["GET"])
@jwt_required()
def get_all_templates():
    try:
        user_email = get_jwt_identity()
        templates = list(templates_collection.find({"user_email": user_email}, {"_id": 1, "template_name": 1, "subject": 1, "body": 1}))

        for template in templates:
            template["_id"] = str(template["_id"])

        return jsonify({"templates": templates}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    




# --------------------------Retrieve a Single Template by ID----------------------------
@app.route("/template/<template_id>", methods=["GET"])
@jwt_required()
def get_template(template_id):
    try:
        user_email = get_jwt_identity()
        template = templates_collection.find_one({"_id": ObjectId(template_id), "user_email": user_email})

        if not template:
            return jsonify({"message": "Template not found"}), 404

        template["_id"] = str(template["_id"])
        return jsonify(template), 200

    except Exception as e:
        return jsonify({"error": "Invalid template ID" if "ObjectId" in str(e) else str(e)}), 400

# --------------------------Update a Single Template by ID----------------------------
@app.route("/template/<template_id>", methods=["PUT"])
@jwt_required()
def update_template(template_id):
    user_id = get_jwt_identity()  # Get user ID from JWT token
    data = request.json

    # Check if template exists
    template = templates_collection.find_one({"_id": ObjectId(template_id)})
    if not template:
        return jsonify({"message": "Template not found"}), 404

    update_data = {}
    if "template_name" in data:
        update_data["template_name"] = data["template_name"]
    if "subject" in data:
        update_data["subject"] = data["subject"]
    if "body" in data:
        update_data["body"] = data["body"]

    if not update_data:
        return jsonify({"message": "No valid fields to update"}), 400

    templates_collection.update_one({"_id": ObjectId(template_id)}, {"$set": update_data})

    return jsonify({"message": "Template updated successfully"}), 200

# --------------------------Delete a Single Template by ID----------------------------
@app.route("/template/<template_id>", methods=["DELETE"])
@jwt_required()
def delete_template(template_id):
    

    # Check if template exists
    template = templates_collection.find_one({"_id": ObjectId(template_id)})
    if not template:
        return jsonify({"message": "Template not found"}), 404

    templates_collection.delete_one({"_id": ObjectId(template_id)})

    return jsonify({"message": "Template deleted successfully"}), 200



if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)

    

