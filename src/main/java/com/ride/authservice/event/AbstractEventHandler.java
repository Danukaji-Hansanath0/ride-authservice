package com.ride.authservice.event;

public abstract class AbstractEventHandler<T extends BaseEvent> implements EventHandler<T>{
    private final Class<T> eventType;
    private final int priority;

    protected AbstractEventHandler(Class<T> eventType, int priority) {
        this.eventType = eventType;
        this.priority = priority;
    }

    @Override
    public abstract void handle(T event);

    @Override
    public boolean canHandle(BaseEvent event) {
        return eventType.isAssignableFrom(event.getClass());
    }

    @Override
    public int getPriority() {
        return priority;
    }
}
