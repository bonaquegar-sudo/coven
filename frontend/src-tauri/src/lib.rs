use tauri_plugin_shell::ShellExt;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
  tauri::Builder::default()
    .plugin(tauri_plugin_dialog::init())
    .plugin(tauri_plugin_shell::init())
    .setup(|app| {
      if cfg!(debug_assertions) {
        app.handle().plugin(
          tauri_plugin_log::Builder::default()
            .level(log::LevelFilter::Info)
            .build(),
        )?;
      } else {
        // Bundled Python backend. It exits on its own when this process ends and closes its stdin
        // (see backend/server.py), so there is nothing to clean up here.
        let (_events, child) = app.shell().sidecar("coven-backend")?.args(["8000", "--exit-with-stdin"]).spawn()?;
        std::mem::forget(child); // keep the stdin pipe open for the app's lifetime
      }
      Ok(())
    })
    .run(tauri::generate_context!())
    .expect("error while building tauri application");
}
