package uz.qalqon.security.ui

import android.Manifest
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedContent
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import uz.qalqon.security.MainViewModel
import uz.qalqon.security.R
import uz.qalqon.security.data.ThemeMode
import uz.qalqon.security.model.*
import uz.qalqon.security.ui.theme.QalqonTheme
import java.text.DateFormat
import java.util.Date

private enum class Tab(val label: Int, val icon: ImageVector) {
    HOME(R.string.home, Icons.Default.Home), PROTECTION(R.string.protection, Icons.Default.Shield), SCAN(R.string.scan, Icons.Default.Search), REPORTS(R.string.reports, Icons.Default.Assessment), SETTINGS(R.string.settings, Icons.Default.Settings)
}

@Composable fun QalqonRoot(vm: MainViewModel) {
    val settings by vm.settings.collectAsStateWithLifecycle()
    QalqonTheme(settings.theme) {
        Surface(Modifier.fillMaxSize()) {
            when {
                !settings.loaded -> Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) { CircularProgressIndicator() }
                !settings.onboardingDone -> Onboarding(vm)
                else -> MainShell(vm)
            }
        }
    }
}

@Composable private fun Onboarding(vm: MainViewModel) {
    var page by remember { mutableIntStateOf(0) }
    val context = androidx.compose.ui.platform.LocalContext.current
    val notificationLauncher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { }
    Column(Modifier.fillMaxSize().padding(28.dp), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.Center) {
        Image(painterResource(R.drawable.qalqon_master), null, Modifier.size(150.dp).clip(RoundedCornerShape(34.dp)), contentScale = ContentScale.Crop)
        Spacer(Modifier.height(28.dp))
        AnimatedContent(page, label = "onboarding") { p ->
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Text(when(p){0->"QALQON";1->stringResource(R.string.onboarding_features_title);2->stringResource(R.string.privacy_title);else->stringResource(R.string.protection_setup)}, fontSize = 28.sp, fontWeight = FontWeight.Bold)
                Spacer(Modifier.height(14.dp))
                Text(when(p){0->stringResource(R.string.tagline);1->stringResource(R.string.onboarding_features);2->stringResource(R.string.privacy_text);else->stringResource(R.string.notification_explain)}, style = MaterialTheme.typography.bodyLarge)
            }
        }
        Spacer(Modifier.height(30.dp))
        Button(onClick = {
            if (page < 3) page++ else {
                if (Build.VERSION.SDK_INT >= 33 && ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) != android.content.pm.PackageManager.PERMISSION_GRANTED) notificationLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                vm.completeOnboarding()
            }
        }, modifier = Modifier.fillMaxWidth()) { Text(if(page < 3) stringResource(R.string.continue_text) else stringResource(R.string.finish_setup)) }
    }
}

@Composable private fun MainShell(vm: MainViewModel) {
    var tab by remember { mutableStateOf(Tab.HOME) }
    var selectedApp by remember { mutableStateOf<AppSecurityInfo?>(null) }
    val error by vm.error.collectAsStateWithLifecycle()
    if (error != null) AlertDialog(onDismissRequest = vm::clearError, confirmButton = { TextButton(onClick=vm::clearError){Text("OK")} }, title={Text("QALQON")}, text={Text(error ?: "")})
    Scaffold(
        bottomBar = {
            NavigationBar {
                Tab.entries.forEach { item -> NavigationBarItem(selected = tab==item, onClick={tab=item; selectedApp=null}, icon={Icon(item.icon,null)}, label={Text(stringResource(item.label))}) }
            }
        }
    ) { padding ->
        Box(Modifier.padding(padding).fillMaxSize()) {
            if (selectedApp != null) AppDetail(selectedApp!!){selectedApp=null} else when(tab) {
                Tab.HOME -> Dashboard(vm)
                Tab.PROTECTION -> Protection(vm, onApp={selectedApp=it})
                Tab.SCAN -> ScanScreen(vm)
                Tab.REPORTS -> Reports(vm)
                Tab.SETTINGS -> SettingsScreen(vm)
            }
        }
    }
}

@Composable private fun Dashboard(vm: MainViewModel) {
    val s by vm.dashboard.collectAsStateWithLifecycle()
    LazyColumn(Modifier.fillMaxSize(), contentPadding = PaddingValues(18.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
        item {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Image(painterResource(R.drawable.qalqon_master), null, Modifier.size(58.dp).clip(RoundedCornerShape(15.dp)))
                Spacer(Modifier.width(12.dp)); Column { Text("QALQON", fontSize=24.sp,fontWeight=FontWeight.Bold); Text(stringResource(R.string.protection_active), color=Color(0xFF25B46B)) }
            }
        }
        item { GlassCard { Column(horizontalAlignment=Alignment.CenterHorizontally, modifier=Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.overall_security), style=MaterialTheme.typography.titleMedium); Spacer(Modifier.height(10.dp)); SecurityRing(s.overallSecurityScore, s.loading); Spacer(Modifier.height(8.dp))
            Text(stringResource(R.string.real_data_note), style=MaterialTheme.typography.bodySmall)
            if (s.loading && s.scanTotal>0) { Spacer(Modifier.height(10.dp)); LinearProgressIndicator(progress={s.scanProcessed.toFloat()/s.scanTotal}); Text("${s.scanProcessed} / ${s.scanTotal}") }
            Spacer(Modifier.height(8.dp)); Button(onClick=vm::refreshAll, enabled=!s.loading){Text(stringResource(R.string.scan_now))}
        } } }
        item { Row(Modifier.fillMaxWidth(), horizontalArrangement=Arrangement.spacedBy(10.dp)) { ScoreCard(stringResource(R.string.app_security), s.appSecurityScore, Modifier.weight(1f)); ScoreCard(stringResource(R.string.permission_security), s.permissionSecurityScore, Modifier.weight(1f)) } }
        item { Row(Modifier.fillMaxWidth(), horizontalArrangement=Arrangement.spacedBy(10.dp)) { ScoreCard(stringResource(R.string.device_security), s.deviceSecurityScore, Modifier.weight(1f)); ScoreCard(stringResource(R.string.web_security), s.webSecurityScore, Modifier.weight(1f)) } }
        item { GlassCard { Column { Text(stringResource(R.string.installed_apps), fontWeight=FontWeight.Bold); Spacer(Modifier.height(8.dp)); StatRow(stringResource(R.string.installed_apps), s.totalApps); StatRow(stringResource(R.string.safe), s.safeApps); StatRow(stringResource(R.string.attention), s.attentionApps); StatRow(stringResource(R.string.suspicious), s.suspiciousApps); StatRow(stringResource(R.string.high_risk), s.highRiskApps) } } }
        s.device?.let { d -> item { DeviceCard(d) } }
    }
}

@Composable private fun SecurityRing(score: Int?, loading: Boolean) {
    Box(Modifier.size(170.dp), contentAlignment=Alignment.Center) {
        Canvas(Modifier.fillMaxSize()) {
            drawArc(Color.Gray.copy(alpha=.18f), -90f, 360f, false, style=Stroke(16.dp.toPx(), cap=StrokeCap.Round))
            if (score != null) drawArc(if(score>=80) Color(0xFF25B46B) else if(score>=55) Color(0xFFFFB020) else Color(0xFFE5484D), -90f, 360f*score/100f, false, style=Stroke(16.dp.toPx(), cap=StrokeCap.Round))
        }
        if (loading && score==null) CircularProgressIndicator() else Text(score?.let{"$it%"} ?: "—", fontSize=38.sp, fontWeight=FontWeight.Bold)
    }
}

@Composable private fun ScoreCard(title:String, score:Int?, modifier:Modifier=Modifier) { GlassCard(modifier){ Column { Text(title, style=MaterialTheme.typography.labelLarge); Text(score?.let{"$it%"} ?: "—", fontSize=27.sp,fontWeight=FontWeight.Bold) } } }
@Composable private fun StatRow(name:String,value:Int){Row(Modifier.fillMaxWidth().padding(vertical=4.dp),horizontalArrangement=Arrangement.SpaceBetween){Text(name);Text(value.toString(),fontWeight=FontWeight.SemiBold)}}
@Composable private fun GlassCard(modifier:Modifier=Modifier, content:@Composable ()->Unit){Surface(modifier,shape=RoundedCornerShape(24.dp),tonalElevation=2.dp,color=MaterialTheme.colorScheme.surface.copy(alpha=.92f)){Box(Modifier.padding(18.dp)){content()}}}

@Composable private fun DeviceCard(d: DeviceSecurityInfo) { GlassCard { Column(verticalArrangement=Arrangement.spacedBy(5.dp)) { Text(stringResource(R.string.device_info),fontWeight=FontWeight.Bold); Text("${d.manufacturer} ${d.model}"); Text("${stringResource(R.string.android_version)} ${d.androidVersion} (API ${d.sdk})"); Text("${stringResource(R.string.security_patch)}: ${d.securityPatch}"); Text("${stringResource(R.string.screen_lock)}: ${if(d.screenLockSecure) stringResource(R.string.active) else stringResource(R.string.inactive)}"); Text("${stringResource(R.string.developer_options)}: ${if(d.developerOptions) stringResource(R.string.active) else stringResource(R.string.inactive)}") } } }

@Composable private fun Protection(vm: MainViewModel, onApp:(AppSecurityInfo)->Unit) {
    val apps by vm.apps.collectAsStateWithLifecycle(); var query by remember { mutableStateOf("") }
    val shown = remember(apps,query){ if(query.isBlank()) apps else apps.filter{it.label.contains(query,true)||it.packageName.contains(query,true)} }
    Column(Modifier.fillMaxSize().padding(16.dp)) {
        Text(stringResource(R.string.protection),fontSize=28.sp,fontWeight=FontWeight.Bold); Spacer(Modifier.height(12.dp))
        OutlinedTextField(query,{query=it},Modifier.fillMaxWidth(),label={Text(stringResource(R.string.search_apps))},singleLine=true)
        Spacer(Modifier.height(10.dp))
        LazyColumn(verticalArrangement=Arrangement.spacedBy(8.dp)) { items(shown,key={it.packageName}) { app -> AppRow(app){onApp(app)} } }
    }
}

@Composable private fun AppRow(app:AppSecurityInfo,onClick:()->Unit) { Card(onClick=onClick,shape=RoundedCornerShape(20.dp)){Row(Modifier.fillMaxWidth().padding(12.dp),verticalAlignment=Alignment.CenterVertically){val icon=rememberAppIcon(app.packageName); if(icon!=null) Image(icon,null,Modifier.size(48.dp).clip(RoundedCornerShape(12.dp))) else Box(Modifier.size(48.dp).background(MaterialTheme.colorScheme.surfaceVariant,CircleShape),contentAlignment=Alignment.Center){Text(app.label.take(1))}; Spacer(Modifier.width(12.dp));Column(Modifier.weight(1f)){Text(app.label,fontWeight=FontWeight.SemiBold,maxLines=1,overflow=TextOverflow.Ellipsis);Text(app.packageName,style=MaterialTheme.typography.bodySmall,maxLines=1,overflow=TextOverflow.Ellipsis)};RiskBadge(app.riskScore,app.category)}} }

@Composable private fun RiskBadge(score:Int,category:RiskCategory){val c=when(category){RiskCategory.SAFE,RiskCategory.LOW->Color(0xFF25B46B);RiskCategory.ATTENTION->Color(0xFFFFB020);else->Color(0xFFE5484D)};Surface(color=c.copy(alpha=.15f),shape=RoundedCornerShape(30.dp)){Text("$score%",Modifier.padding(horizontal=10.dp,vertical=6.dp),color=c,fontWeight=FontWeight.Bold)}}

@Composable private fun AppDetail(app:AppSecurityInfo,onBack:()->Unit){LazyColumn(Modifier.fillMaxSize(),contentPadding=PaddingValues(18.dp),verticalArrangement=Arrangement.spacedBy(12.dp)){item{TextButton(onClick=onBack){Icon(Icons.Default.ArrowBack,null);Text(stringResource(R.string.back))}};item{Row(verticalAlignment=Alignment.CenterVertically){rememberAppIcon(app.packageName)?.let{Image(it,null,Modifier.size(72.dp).clip(RoundedCornerShape(18.dp)));Spacer(Modifier.width(14.dp))};Column{Text(app.label,fontSize=25.sp,fontWeight=FontWeight.Bold);Text(app.packageName);RiskBadge(app.riskScore,app.category)}}};item{GlassCard{Column{Text(stringResource(R.string.details),fontWeight=FontWeight.Bold);Text("${stringResource(R.string.version)}: ${app.versionName}");Text("${stringResource(R.string.target_sdk)}: ${app.targetSdk}");Text("${stringResource(R.string.source)}: ${app.installerPackage ?: stringResource(R.string.unknown)}");Text("${stringResource(R.string.certificate)}: ${app.certificateSha256 ?: stringResource(R.string.unknown)}")}}};item{GlassCard{Column{Text(stringResource(R.string.permissions),fontWeight=FontWeight.Bold);Text("${app.grantedPermissions.size} / ${app.requestedPermissions.size}");app.reasons.forEach{Text("• ${it.title}: ${it.detail}",Modifier.padding(top=5.dp))};if(app.reasons.isEmpty())Text(stringResource(R.string.no_known_risk));Spacer(Modifier.height(8.dp));Text(stringResource(R.string.not_proof_malware),style=MaterialTheme.typography.bodySmall)}}}}

@Composable private fun ScanScreen(vm:MainViewModel){var mode by remember{mutableIntStateOf(0)}; val apk by vm.apkResult.collectAsStateWithLifecycle();val url by vm.urlResult.collectAsStateWithLifecycle();var link by remember{mutableStateOf("")};val launcher=rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()){it?.let(vm::scanApk)};LazyColumn(Modifier.fillMaxSize(),contentPadding=PaddingValues(18.dp),verticalArrangement=Arrangement.spacedBy(12.dp)){item{Text(stringResource(R.string.scan),fontSize=28.sp,fontWeight=FontWeight.Bold)};item{SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()){listOf(R.string.full_scan,R.string.apk_scan,R.string.link_scan).forEachIndexed{i,id->SegmentedButton(selected=mode==i,onClick={mode=i},shape=SegmentedButtonDefaults.itemShape(i,3)){Text(stringResource(id))}}}};when(mode){0->item{GlassCard{Column{Text(stringResource(R.string.full_scan),fontWeight=FontWeight.Bold);Spacer(Modifier.height(8.dp));Text(stringResource(R.string.real_data_note));Spacer(Modifier.height(10.dp));Button(onClick=vm::refreshAll){Text(stringResource(R.string.scan_now))}}}};1->{item{Button(onClick={launcher.launch(arrayOf("application/vnd.android.package-archive","application/octet-stream"))},Modifier.fillMaxWidth()){Text(stringResource(R.string.choose_apk))}};apk?.let{r->item{ResultCard(r.displayName,r.riskScore,r.category,listOf("${stringResource(R.string.package_name)}: ${r.packageName ?: "—"}","${stringResource(R.string.sha256)}: ${r.sha256}","${stringResource(R.string.cloud_reputation)}: ${r.reputation}")+r.reasons.map{"${it.title}: ${it.detail}"})}}};else->{item{OutlinedTextField(link,{link=it},Modifier.fillMaxWidth(),label={Text(stringResource(R.string.paste_link))},singleLine=true)};item{Button(onClick={vm.scanUrl(link)},Modifier.fillMaxWidth()){Text(stringResource(R.string.check_link))}};url?.let{r->item{ResultCard(r.host,r.riskScore,r.category,listOf("URL: ${r.normalizedUrl}","${stringResource(R.string.cloud_reputation)}: ${r.reputation}")+r.reasons.map{"${it.title}: ${it.detail}"})}}}}}}

@Composable private fun ResultCard(title:String,score:Int,cat:RiskCategory,lines:List<String>){GlassCard{Column{Text(title,fontWeight=FontWeight.Bold);Spacer(Modifier.height(6.dp));RiskBadge(score,cat);Spacer(Modifier.height(10.dp));lines.forEach{Text(it,style=MaterialTheme.typography.bodySmall,modifier=Modifier.padding(vertical=2.dp))};if(lines.size<=2)Text(stringResource(R.string.no_known_risk))}}}

@Composable private fun Reports(vm:MainViewModel){val history by vm.history.collectAsStateWithLifecycle();LaunchedEffect(Unit){vm.loadHistory()};LazyColumn(Modifier.fillMaxSize(),contentPadding=PaddingValues(18.dp),verticalArrangement=Arrangement.spacedBy(10.dp)){item{Text(stringResource(R.string.reports),fontSize=28.sp,fontWeight=FontWeight.Bold)};if(history.isEmpty())item{Text(stringResource(R.string.history_empty))}else items(history,key={it.id}){h->GlassCard{Column{Text(DateFormat.getDateTimeInstance().format(Date(h.timestamp)),fontWeight=FontWeight.Bold);Text("${stringResource(R.string.overall_security)}: ${h.overallScore}%");Text("${stringResource(R.string.installed_apps)}: ${h.totalApps}");Text("${stringResource(R.string.suspicious)}: ${h.suspiciousApps}   ${stringResource(R.string.high_risk)}: ${h.highRiskApps}")}}}}}

@Composable private fun SettingsScreen(vm:MainViewModel){val settings by vm.settings.collectAsStateWithLifecycle();LazyColumn(Modifier.fillMaxSize(),contentPadding=PaddingValues(18.dp),verticalArrangement=Arrangement.spacedBy(12.dp)){item{Text(stringResource(R.string.settings),fontSize=28.sp,fontWeight=FontWeight.Bold)};item{GlassCard{Column{Text(stringResource(R.string.theme),fontWeight=FontWeight.Bold);ThemeMode.entries.forEach{m->Row(Modifier.fillMaxWidth(),verticalAlignment=Alignment.CenterVertically){RadioButton(selected=settings.theme==m,onClick={vm.setTheme(m)});Text(when(m){ThemeMode.SYSTEM->stringResource(R.string.theme_system);ThemeMode.LIGHT->stringResource(R.string.theme_light);ThemeMode.DARK->stringResource(R.string.theme_dark)})}}}}};item{GlassCard{Column{Text(stringResource(R.string.background_protection),fontWeight=FontWeight.Bold);Text(stringResource(R.string.daily_refresh));Text(if(vm.cloudConfigured())"Cloud reputation: HTTPS configured" else stringResource(R.string.cloud_not_configured),style=MaterialTheme.typography.bodySmall)}}};item{GlassCard{Column{Row(verticalAlignment=Alignment.CenterVertically){Image(painterResource(R.drawable.qalqon_master),null,Modifier.size(58.dp).clip(RoundedCornerShape(14.dp)));Spacer(Modifier.width(12.dp));Text("QALQON",fontSize=23.sp,fontWeight=FontWeight.Bold)};Spacer(Modifier.height(10.dp));Text(stringResource(R.string.about_text))}}}}
