package com.ride.authservice.event;

import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class EventPublisher {
    private final Map<Class<?>, List<EventHandler<?>>> handlers = new ConcurrentHashMap<>();

    public <T extends BaseEvent> void subscribe(Class<T> eventType, EventHandler<T> handler) {
        handlers.computeIfAbsent(eventType, k -> new ArrayList<>()).add(handler);
        sortHandlersByPriority(eventType);
    }
    @SuppressWarnings("unchecked")
    public void publish(BaseEvent event) {
        List<EventHandler<?>> eventHandlers = handlers.get(event.getClass());
        if (eventHandlers != null) {
            eventHandlers.forEach(handler -> {
                if (handler.canHandle(event)) {
                    ((EventHandler<BaseEvent>) handler).handle(event);
                }
            });
        }
    }

    private void sortHandlersByPriority(Class<?> eventType) {
        handlers.get(eventType).sort(Comparator.comparingInt(EventHandler::getPriority));
    }


}
