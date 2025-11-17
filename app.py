from flask import Flask, render_template, request, Response, stream_with_context, jsonify # <-- MODIFIED (added jsonify)
import os
import subprocess
from datetime import datetime
import time
import json
from urllib.parse import unquote

# --- FLASK CONFIG ---
app = Flask(__name__, static_folder='static')
UPLOAD_FOLDER = 'uploads'
RESULTS_FOLDER = 'analysis_results'
SCRIPTS_FOLDER = 'scripts'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(RESULTS_FOLDER, exist_ok=True)
os.makedirs(SCRIPTS_FOLDER, exist_ok=True)

# Allow .zip, .7z, and .rar since the frontend accepts them and 7-Zip can handle them all.
ALLOWED_EXTENSIONS = {'zip', '7z', 'rar'} # <-- MODIFIED

# --- VIRTUALBOX CONFIGURATION ---
VBOX_MANAGE_PATH = r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
BASE_VM_NAME = "Windows-ent-10"
START_TYPE = "gui"

# --- GUEST VM CREDENTIALS & PATHS ---
VM_USERNAME = "Stage.Ali"
VM_PASSWORD = "StrongPassword1234"
VM_DESTINATION_FOLDER = "C:\\Users\\Stage.Ali\\Desktop\\Malware"
VM_RESULTS_FOLDER = "C:\\Users\\Stage.Ali\\Desktop\\DetonationResults"
VM_PS1_PATH = "C:\\Detonation\\run.ps1"
# <-- NEW: Path to 7-Zip executable inside the guest VM.
# IMPORTANT: You must install 7-Zip on your base VM for this to work.
VM_7ZIP_PATH = "C:\\Program Files\\7-Zip\\7z.exe"


# --- HELPERS ---
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def run_vbox_command(command):
    """Execute VBoxManage command and capture output."""
    print(f"▶️ Executing: {' '.join(command)}")
    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True, encoding='utf-8', errors='ignore')
        print("✅ Success")
        return True, result.stdout
    except subprocess.CalledProcessError as e:
        print(f"❌ Error executing command. Return Code: {e.returncode}")
        print(f"Stderr: {e.stderr}")
        return False, f"Return Code: {e.returncode}\n{e.stderr}"
    except FileNotFoundError:
        return False, f"VBoxManage not found at {VBOX_MANAGE_PATH}"

def delete_vm(clone_vm_name):
    """Power off and delete a VM clone, with checks and a delay."""
    print(f"--- 🧹 Starting cleanup for {clone_vm_name} ---")
    print(f"Attempting to power off {clone_vm_name}...")
    run_vbox_command([VBOX_MANAGE_PATH, "controlvm", clone_vm_name, "poweroff"])
    print("Waiting 2 seconds for VM services to release file locks...")
    time.sleep(2)
    print(f"Attempting to unregister and delete {clone_vm_name}...")
    success, output = run_vbox_command([VBOX_MANAGE_PATH, "unregistervm", clone_vm_name, "--delete"])
    if success:
        print(f"✅ Successfully deleted VM: {clone_vm_name}")
    else:
        print(f"❌ CRITICAL: Failed to delete VM: {clone_vm_name}")
        print(f"Error details: {output}")
    print(f"--- 🧹 Cleanup for {clone_vm_name} finished ---")


# --- STREAMING LOGIC ---
# <-- MODIFIED: Function now accepts zip_password
def generate_analysis_stream(files, zip_password):
    """
    This generator takes your original analysis logic and yields status updates
    to the frontend without changing the core commands.
    """
    for file_index, file in enumerate(files):
        file_id = f"file-{file_index}"
        
        if not file or not allowed_file(file.filename):
            error_msg = "Invalid file type." if file else "Invalid file provided."
            yield f"data: {json.dumps({'id': file_id, 'filename': file.filename if file else 'N/A', 'status': 'error', 'message': error_msg})}\n\n"
            continue

        yield f"data: {json.dumps({'id': file_id, 'filename': file.filename, 'status': 'info', 'message': 'File accepted. Saving locally...'})}\n\n"
        
        # Save uploaded file
        relative_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(relative_path)
        absolute_path = os.path.abspath(relative_path)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        clone_vm_name = f"{BASE_VM_NAME}_Clone_{os.path.splitext(file.filename)[0]}_{timestamp}"
        result_data = {"id": file_id, "filename": file.filename, "clone_name": clone_vm_name}

        try:
            # Step 1: Clone VM
            yield f"data: {json.dumps({'id': file_id, 'message': f'Cloning sandbox: {clone_vm_name}', 'step': 1})}\n\n"
            success, output = run_vbox_command([VBOX_MANAGE_PATH, "clonevm", BASE_VM_NAME, "--name", clone_vm_name, "--register"])
            if not success:
                result_data.update({"status": "error", "message": f"Clone failed: {output}"})
                yield f"data: {json.dumps(result_data)}\n\n"
                continue

            # Step 2: Start VM
            yield f"data: {json.dumps({'id': file_id, 'message': 'Starting virtual machine...', 'step': 2})}\n\n"
            success, output = run_vbox_command([VBOX_MANAGE_PATH, "startvm", clone_vm_name, "--type", START_TYPE])
            if not success:
                result_data.update({"status": "error", "message": f"Failed to start VM: {output}"})
                yield f"data: {json.dumps(result_data)}\n\n"
                continue 

            # Wait for Guest Additions
            yield f"data: {json.dumps({'id': file_id, 'message': 'Waiting for VM to boot (60s)...', 'step': 3})}\n\n"
            time.sleep(60)

            # Step 3: Copy Archive into VM
            yield f"data: {json.dumps({'id': file_id, 'message': f'Copying {file.filename} to guest...', 'step': 4})}\n\n"
            vm_zip_path = f"{VM_DESTINATION_FOLDER}\\{file.filename}"
            success, output = run_vbox_command([VBOX_MANAGE_PATH, "guestcontrol", clone_vm_name, "copyto", absolute_path, vm_zip_path, "--username", VM_USERNAME, "--password", VM_PASSWORD])
            if not success:
                result_data.update({"status": "error", "message": f"Copy failed: {output}"})
                yield f"data: {json.dumps(result_data)}\n\n"
                continue

            # Step 4: Copy run.ps1 into VM
            yield f"data: {json.dumps({'id': file_id, 'message': 'Copying analysis script to guest...', 'step': 5})}\n\n"
            local_ps1 = os.path.abspath(os.path.join(SCRIPTS_FOLDER, "run.ps1"))
            success, output = run_vbox_command([VBOX_MANAGE_PATH, "guestcontrol", clone_vm_name, "copyto", local_ps1, VM_PS1_PATH, "--username", VM_USERNAME, "--password", VM_PASSWORD])
            if not success:
                result_data.update({"status": "error", "message": f"Failed to copy run.ps1: {output}"})
                yield f"data: {json.dumps(result_data)}\n\n"
                continue

            # ############################################################### #
            # <-- MODIFIED: Unzip inside VM using 7-Zip for password support
            # ############################################################### #
            yield f"data: {json.dumps({'id': file_id, 'message': 'Extracting archive in guest...', 'step': 6})}\n\n"
            
            # Base 7-Zip command arguments: x = extract with full paths, -o = output dir, -y = yes to all
            seven_zip_args = ["x", vm_zip_path, f"-o{VM_DESTINATION_FOLDER}", "-y"]
            
            # Conditionally add the password argument if it was provided
            if zip_password:
                yield f"data: {json.dumps({'id': file_id, 'message': 'Applying password to archive...', 'step': 6})}\n\n"
                seven_zip_args.append(f"-p{zip_password}") # The -p switch for password (no space)

            unzip_cmd = [
                VBOX_MANAGE_PATH, "guestcontrol", clone_vm_name, "run",
                "--exe", VM_7ZIP_PATH,
                "--username", VM_USERNAME,
                "--password", VM_PASSWORD,
                "--"
            ] + seven_zip_args

            success, output = run_vbox_command(unzip_cmd)
            # Check for specific 7-Zip errors like a wrong password
            if not success:
                error_message = f"Failed to extract archive: {output}"
                if "Wrong Password" in output:
                    error_message = "Extraction failed: The password provided was incorrect."
                result_data.update({"status": "error", "message": error_message})
                yield f"data: {json.dumps(result_data)}\n\n"
                continue
            # ############################################################### #

            # Step 5b: Find the extracted EXE
            yield f"data: {json.dumps({'id': file_id, 'message': 'Searching for executable in archive...', 'step': 7})}\n\n"
            list_exe_cmd = [VBOX_MANAGE_PATH, "guestcontrol", clone_vm_name, "run", "--exe", "cmd.exe", "--username", VM_USERNAME, "--password", VM_PASSWORD, "--", "cmd", "/c", f"dir {VM_DESTINATION_FOLDER}\\*.exe /s /b"]
            success, output = run_vbox_command(list_exe_cmd)
            if not (success and output.strip()):
                result_data.update({"status": "error", "message": f"No EXE found in archive: {output}"})
                yield f"data: {json.dumps(result_data)}\n\n"
                continue
            malware_exe = output.strip().splitlines()[0].strip()
            
            # Step 6: Run detonation script
            yield f"data: {json.dumps({'id': file_id, 'message': f'Detonating {os.path.basename(malware_exe)} (Timeout: 120s)...', 'step': 8})}\n\n"
            detonation_cmd = [VBOX_MANAGE_PATH, "guestcontrol", clone_vm_name, "run", "--exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "--username", VM_USERNAME, "--password", VM_PASSWORD, "--", "powershell", "-ExecutionPolicy", "Bypass", "-File", VM_PS1_PATH, "-ExePath", malware_exe, "-TimeoutSec", "120"]
            run_vbox_command(detonation_cmd)

            # Step 7: Move results
            yield f"data: {json.dumps({'id': file_id, 'message': 'Collecting analysis artifacts in guest...', 'step': 9})}\n\n"
            collect_cmd = [VBOX_MANAGE_PATH, "guestcontrol", clone_vm_name, "run", "--exe", "cmd.exe", "--username", VM_USERNAME, "--password", VM_PASSWORD, "--", "cmd", "/c", f"xcopy C:\\Detonation\\Runs\\* {VM_RESULTS_FOLDER} /E /Y"]
            run_vbox_command(collect_cmd)

            # Step 8: Copy results back to host
            yield f"data: {json.dumps({'id': file_id, 'message': 'Copying results back to host...', 'step': 10})}\n\n"
            local_results = os.path.join(RESULTS_FOLDER, clone_vm_name)
            os.makedirs(local_results, exist_ok=True)
            copyback_cmd = [VBOX_MANAGE_PATH, "guestcontrol", clone_vm_name, "copyfrom", f"{VM_RESULTS_FOLDER}\\", local_results, "--username", VM_USERNAME, "--password", VM_PASSWORD, "--recursive"]
            run_vbox_command(copyback_cmd)

            result_data.update({"status": "complete", "message": "Analysis successful!", "results_path": local_results})
            yield f"data: {json.dumps(result_data)}\n\n"

        except Exception as e:
            result_data.update({"status": "error", "message": f"An unexpected server error occurred: {str(e)}"})
            yield f"data: {json.dumps(result_data)}\n\n"
        finally:
            yield f"data: {json.dumps({'id': file_id, 'message': 'Cleaning up sandbox environment...', 'step': 11})}\n\n"
            if os.path.exists(absolute_path):
                os.remove(absolute_path)
            delete_vm(clone_vm_name)
            yield f"data: {json.dumps({'id': file_id, 'message': 'Cleanup complete.', 'step': 12})}\n\n"

# --- ROUTES ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze_files_route():
    uploaded_files = request.files.getlist("files")
    if not uploaded_files or all(f.filename == '' for f in uploaded_files):
        return jsonify([{"error": "No selected files"}]), 400

    # <-- NEW: Get the password from the form. .get() returns None if it's not present.
    zip_password = request.form.get('zip_password')

    # <-- MODIFIED: Pass the password to the generator function.
    return Response(stream_with_context(generate_analysis_stream(uploaded_files, zip_password)), mimetype='text/event-stream')

@app.route('/api/reports')
def get_reports():
    try:
        dirs = [d for d in os.listdir(RESULTS_FOLDER) if os.path.isdir(os.path.join(RESULTS_FOLDER, d))]
        return jsonify(dirs)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/reports/<path:analysis_dir>')
def get_analysis_files(analysis_dir):
    try:
        dir_path = os.path.join(RESULTS_FOLDER, analysis_dir)
        if not os.path.exists(dir_path):
            return jsonify({"error": "Directory not found"}), 404
        json_files = []
        for root, dirs, files in os.walk(dir_path):
            for file in files:
                if file.endswith('.json'):
                    # Get relative path from dir_path
                    rel_path = os.path.relpath(os.path.join(root, file), dir_path)
                    # Replace backslashes with forward slashes for web compatibility
                    rel_path = rel_path.replace('\\', '/')
                    json_files.append(rel_path)
        return jsonify(json_files)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/reports/<path:analysis_dir>/<path:filename>')
def get_file_content(analysis_dir, filename):
    try:
        analysis_dir = unquote(analysis_dir)
        filename = unquote(filename)
        file_path = os.path.join(RESULTS_FOLDER, analysis_dir, filename.replace('/', os.sep))
        if not os.path.exists(file_path):
            return jsonify({"error": "File not found"}), 404
        if filename.endswith('.json'):
            with open(file_path, 'r') as f:
                content = json.load(f)
            return jsonify(content)
        else:
            return jsonify({"error": "Only JSON files supported"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/reports/file')
def get_file_content_query():
    """
    Safer file fetch using query parameters: /api/reports/file?analysis=<analysis_dir>&file=<path/to/file.json>
    This avoids ambiguity with percent-encoded slashes in path segments and normalizes paths to prevent traversal.
    """
    try:
        analysis_dir = request.args.get('analysis')
        filename = request.args.get('file')
        if not analysis_dir or not filename:
            return jsonify({"error": "Missing 'analysis' or 'file' query parameter"}), 400

        # Normalize incoming values (don't trust client input)
        # Replace forward slashes in the filename with OS separator so callers can pass 'subdir/file.json'
        safe_filename = filename.replace('/', os.sep)

        # Build absolute path and normalize
        joined = os.path.join(RESULTS_FOLDER, analysis_dir, safe_filename)
        file_path = os.path.normpath(joined)
        abs_results = os.path.abspath(RESULTS_FOLDER)
        abs_file = os.path.abspath(file_path)

        # Prevent directory traversal: ensure the resolved file is inside RESULTS_FOLDER
        if not abs_file.startswith(abs_results + os.sep) and abs_file != abs_results:
            return jsonify({"error": "Invalid file path"}), 400

        if not os.path.exists(abs_file):
            return jsonify({"error": "File not found", "path": abs_file}), 404

        if not abs_file.lower().endswith('.json'):
            return jsonify({"error": "Only JSON files supported"}), 400

        # Read JSON with utf-8-sig to gracefully handle files that start with a BOM
        try:
            with open(abs_file, 'r', encoding='utf-8-sig') as f:
                content = json.load(f)
        except json.JSONDecodeError as jde:
            # Return a helpful error showing the problem without crashing
            return jsonify({"error": "Invalid JSON file", "message": str(jde)}), 400
        except Exception as e:
            # Fallback: try reading with replacement to avoid unexpected encoding issues
            with open(abs_file, 'r', encoding='utf-8', errors='replace') as f:
                try:
                    content = json.load(f)
                except Exception as e2:
                    return jsonify({"error": "Failed to parse JSON", "message": str(e2)}), 400

        return jsonify(content)
    except Exception as e:
        import traceback
        tb = traceback.format_exc()
        print(tb)
        return jsonify({"error": str(e), "trace": tb}), 500

if __name__ == '__main__':
    app.run(debug=True, threaded=True)