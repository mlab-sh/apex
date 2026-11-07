package sh.mlab.apex.agent;

import android.service.notification.NotificationListenerService;

/** Full agent only: bound by the system once APEX allows it; DumpProvider reads the active notifications through it. */
public class Listener extends NotificationListenerService {
    static volatile Listener instance;

    @Override
    public void onListenerConnected() {
        instance = this;
    }

    @Override
    public void onListenerDisconnected() {
        instance = null;
    }
}
