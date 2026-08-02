package com.example.pegasusscanner

import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import com.example.pegasusscanner.engine.IocRepository
import com.example.pegasusscanner.engine.ScanEngine
import com.example.pegasusscanner.model.Finding
import com.example.pegasusscanner.model.Indicator
import com.example.pegasusscanner.model.ScanReport
import com.example.pegasusscanner.model.Severity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : ComponentActivity() {

    private lateinit var iocRepository: IocRepository
    private lateinit var scanEngine: ScanEngine

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        iocRepository = IocRepository(this)
        scanEngine = ScanEngine(this)

        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    AppScreen(iocRepository, scanEngine)
                }
            }
        }
    }
}

@Composable
fun AppScreen(iocRepository: IocRepository, scanEngine: ScanEngine) {
    val scope = rememberCoroutineScope()
    var indicators by remember { mutableStateOf<List<Indicator>>(emptyList()) }
    var report by remember { mutableStateOf<ScanReport?>(null) }
    var isScanning by remember { mutableStateOf(false) }
    var statusMessage by remember { mutableStateOf("No indicator file imported yet. Using empty placeholder list.") }

    val importLauncher = rememberLauncherForActivityResultCompat { uri: Uri? ->
        if (uri != null) {
            scope.launch {
                try {
                    val loaded = withContext(Dispatchers.IO) { iocRepository.loadFromUri(uri) }
                    indicators = loaded
                    statusMessage = "Imported ${loaded.size} indicator(s)."
                } catch (e: Exception) {
                    statusMessage = "Failed to parse indicator file: ${e.message}"
                }
            }
        }
    }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item { Text("Spyware Triage Scanner", style = MaterialTheme.typography.headlineSmall) }

        item {
            Card {
                Column(Modifier.padding(12.dp)) {
                    Text(
                        "This is a triage tool, not a guarantee. Sophisticated spyware like " +
                            "Pegasus is designed to leave minimal traces and can infect a device " +
                            "without installing a visible app. This scanner checks installed apps " +
                            "against indicators you import and flags risky permission patterns. " +
                            "For a rigorous check, use Amnesty International's MVT toolkit " +
                            "(github.com/mvt-project/mvt) on a full device/backup image, or consult " +
                            "a digital forensics professional.",
                        style = MaterialTheme.typography.bodySmall
                    )
                }
            }
        }

        item {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = { importLauncher.launch(arrayOf("application/json", "text/plain")) }) {
                    Text("Import IOC file")
                }
                Button(
                    enabled = !isScanning,
                    onClick = {
                        isScanning = true
                        statusMessage = "Scanning installed apps..."
                        scope.launch {
                            val result = withContext(Dispatchers.Default) {
                                scanEngine.runScan(indicators)
                            }
                            report = result
                            isScanning = false
                            statusMessage = "Scan complete."
                        }
                    }
                ) {
                    Text(if (isScanning) "Scanning..." else "Run scan")
                }
            }
        }

        item { Text(statusMessage, style = MaterialTheme.typography.bodySmall) }

        report?.let { r ->
            item {
                Text(
                    "Scanned ${r.scannedAppCount} apps against ${r.indicatorCount} indicator(s). " +
                        "${r.findings.count { it.severity == Severity.HIGH }} high, " +
                        "${r.findings.count { it.severity == Severity.MEDIUM }} medium, " +
                        "${r.findings.count { it.severity == Severity.LOW }} low priority findings.",
                    style = MaterialTheme.typography.titleSmall
                )
            }
            items(r.findings) { finding -> FindingCard(finding) }
        }
    }
}

@Composable
fun FindingCard(finding: Finding) {
    val color = when (finding.severity) {
        Severity.HIGH -> Color(0xFFD32F2F)
        Severity.MEDIUM -> Color(0xFFF57C00)
        Severity.LOW -> Color(0xFFFBC02D)
        Severity.INFO -> Color(0xFF757575)
    }
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    modifier = Modifier
                        .size(10.dp)
                        .background(color, shape = androidx.compose.foundation.shape.CircleShape)
                )
                Spacer(Modifier.width(8.dp))
                Text(finding.title, style = MaterialTheme.typography.titleSmall)
            }
            Spacer(Modifier.height(4.dp))
            Text(finding.detail, style = MaterialTheme.typography.bodySmall)
            finding.packageName?.let {
                Spacer(Modifier.height(2.dp))
                Text("Package: $it", style = MaterialTheme.typography.labelSmall)
            }
        }
    }
}

@Composable
fun rememberLauncherForActivityResultCompat(onResult: (Uri?) -> Unit) =
    androidx.activity.compose.rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument(),
        onResult = onResult
    )
